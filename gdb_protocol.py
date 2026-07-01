"""
GDB Remote Serial Protocol client.

Handles real-world GDB stub quirks:
  - Synchronous send→recv (no early timeout)
  - O-prefixed qRcmd console output
  - monitor phys / monitor virt for physical memory access
  - monitor r cr3 for CR3 register
  - g packet auto-detection of x86 vs x64
"""

import socket
import struct
import re
from typing import Optional, Dict

from structs import PAGE_SIZE


class GdbError(Exception):
    pass

class GdbConnectionError(GdbError):
    pass



class GdbClient:
    def __init__(self, host="127.0.0.1", port=1234, timeout=15.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self.arch = 'x64'
        self.reg_size = 8
        self._rbuf = bytearray()
        self._no_ack = False
        self._max_chunk_size = 480

    # ═══ connection ══════════════════════════════════════════════

    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        # Bulk transfer: disable Nagle so command packets are sent
        # immediately (important when we pipeline many small reads).
        # Enlarge buffers to absorb large responses.
        try:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 * 1024 * 1024)
        except (OSError, AttributeError):
            pass
        self._sock.connect((self.host, self.port))
        self._sock.settimeout(0.3)
        try:
            while self._sock.recv(4096):
                pass
        except (socket.timeout, ConnectionResetError):
            pass
        self._sock.settimeout(self.timeout)
        self._rbuf.clear()
        self._probe_arch()

    def close(self):
        if self._sock:
            try: self._sock.close()
            except: pass
            self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *a):
        self.close()

    # ═══ RSP packet layer (buffered for speed) ══════════════════

    @staticmethod
    def _cksum(data: bytes) -> int:
        return sum(data) & 0xFF

    def _recv1(self) -> bytes:
        """Read 1 byte from socket buffer (refills from network as needed)."""
        if not self._rbuf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise GdbConnectionError("connection closed")
            self._rbuf.extend(chunk)
        b = self._rbuf[:1]
        del self._rbuf[:1]
        return b

    def _recv_n(self, n: int) -> bytes:
        """Read exactly n bytes, refilling buffer from network."""
        while len(self._rbuf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise GdbConnectionError("connection closed")
            self._rbuf.extend(chunk)
        result = bytes(self._rbuf[:n])
        del self._rbuf[:n]
        return result

    def _recv_until(self, marker: bytes) -> bytes:
        """Read bytes until marker found. Returns data before marker.
        Consumes marker from buffer."""
        while True:
            pos = self._rbuf.find(marker)
            if pos >= 0:
                result = bytes(self._rbuf[:pos])
                del self._rbuf[:pos + len(marker)]
                return result
            chunk = self._sock.recv(65536)
            if not chunk:
                raise GdbConnectionError("connection closed")
            self._rbuf.extend(chunk)

    def _read_packet_body(self) -> bytes:
        """Read packet body between '$' and '#' + 2-byte checksum.
        Uses bulk recv for speed — no per-byte syscalls."""
        # Read until '#' — this is the packet content
        data = self._recv_until(b'#')
        # Read 2-byte checksum
        self._recv_n(2)
        # ACK the response unless no-ack mode is active
        if not self._no_ack:
            self._sock.sendall(b'+')
        return bytes(data)

    def _send_packet(self, payload: bytes) -> bytes:
        """Send one RSP packet, return response payload."""
        pkt = b'$' + payload + b'#' + f"{self._cksum(payload):02x}".encode()
        self._sock.sendall(pkt)
        # Read bytes until we see '$' (response start), skipping + and -
        while True:
            # Skip ACK/NAK and stray bytes until we find '$'
            while True:
                c = self._recv1()
                if c == b'$':
                    return self._read_packet_body()
                elif c == b'-':
                    self._sock.sendall(pkt)  # NAK → retransmit
                    break  # restart inner loop
                # '+' or stray: keep reading
            # After retransmit, continue outer loop

    def _send_raw(self, cmd: str) -> bytes:
        return self._send_packet(cmd.encode('ascii'))


    def negotiate_features(self) -> dict:
        """Send qSupported and parse returned feature map.

        Sets _max_chunk_size from PacketSize if reported.
        Returns the raw feature dictionary.
        """
        features: Dict[str, str] = {}
        try:
            resp = self._send_raw('qSupported')
            if resp and not resp.startswith(b'E'):
                for part in resp.split(b';'):
                    if b'=' in part:
                        k, v = part.split(b'=', 1)
                        features[k.decode('ascii', errors='replace')] = \
                            v.decode('ascii', errors='replace')
            ps = features.get('PacketSize')
            if ps:
                # PacketSize is the full RSP frame size.  Leave margin
                # for $...#cc.
                max_pkt = int(ps)
                self._max_chunk_size = max(480, (max_pkt - 32) // 2)
        except Exception:
            pass
        # Many stubs return 511 payload bytes per 'm' request (1022 hex chars)
        # even when they don't advertise PacketSize.  Use the larger value.
        self._max_chunk_size = max(self._max_chunk_size, 511)
        return features

    # ═══ architecture detection ═════════════════════════════════

    def _probe_arch(self):
        """Detect x86 vs x64 from g packet register values."""
        try:
            raw_hex = self._send_raw('g')
            raw = bytes.fromhex(raw_hex.decode())

            if len(raw) >= 8:
                # Check if first register looks like a canonical x64 address
                val0 = struct.unpack_from('<Q', raw, 0)[0]
                # Canonical x64 kernel address: bits 63:48 = 0xFFFF (sign-extended)
                if (val0 >> 48) == 0xFFFF or (val0 >> 48) == 0x0000:
                    # Could be x64 — check if multiple regs look canonical
                    x64_count = 0
                    for i in range(min(8, len(raw) // 8)):
                        v = struct.unpack_from('<Q', raw, i * 8)[0]
                        upper = v >> 48
                        if upper == 0xFFFF or upper == 0x0000:
                            x64_count += 1
                    if x64_count >= 4:
                        self.arch = 'x64'
                        self.reg_size = 8
                        return

            # Fall back to size heuristic
            if len(raw) > 200:
                self.arch = 'x64'; self.reg_size = 8
            elif len(raw) >= 64:
                self.arch = 'x86'; self.reg_size = 4
            else:
                # Default to x64 (the target is known to be x64 Windows)
                self.arch = 'x64'; self.reg_size = 8
        except Exception:
            self.arch = 'x64'; self.reg_size = 8

    # ═══ register access ════════════════════════════════════════

    def read_registers(self) -> bytes:
        """Read all registers (g packet). Returns raw hex string bytes."""
        return self._send_raw('g')

    def read_all_regs_dict(self) -> Dict[str, int]:
        hexdata = self.read_registers()
        if not hexdata:
            return {}
        try:
            raw = bytes.fromhex(hexdata.decode())
        except (ValueError, UnicodeDecodeError):
            return {}

        if self.arch == 'x64':
            # x64 g packet layout (varies by stub, but typically):
            # 16 GP regs (8 bytes each) + rip + eflags + segments
            names = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
                     'r8','r9','r10','r11','r12','r13','r14','r15',
                     'rip','eflags']
            result = {}
            for i, nm in enumerate(names):
                off = i * 8
                if off + 8 <= len(raw):
                    result[nm] = struct.unpack_from('<Q', raw, off)[0]
            # Segment registers (4 bytes each)
            seg_names = ['cs','ss','ds','es','fs','gs']
            seg_off = 18 * 8  # after 18 qwords
            for i, nm in enumerate(seg_names):
                off = seg_off + i * 4
                if off + 4 <= len(raw):
                    result[nm] = struct.unpack_from('<I', raw, off)[0]
            return result
        else:
            names = ['eax','ecx','edx','ebx','esp','ebp','esi','edi',
                     'eip','eflags','cs','ss','ds','es','fs','gs']
            fmt = '<' + 'I' * len(names)
            if len(raw) < struct.calcsize(fmt):
                return {}
            vals = struct.unpack(fmt, raw[:struct.calcsize(fmt)])
            return dict(zip(names, vals))

    # ═══ memory access ══════════════════════════════════════════

    def read_memory(self, addr: int, length: int) -> bytes:
        """Read memory at addr via m packet. Returns raw bytes or b''."""
        if length > 500:
            return self._read_memory_chunked(addr, length)
        resp = self._send_raw(f'm{addr:x},{length:x}')
        if not resp or resp.startswith(b'E'):
            return b''
        try:
            return bytes.fromhex(resp.decode())
        except (ValueError, UnicodeDecodeError):
            return b''

    def _read_memory_chunked(self, addr: int, length: int) -> bytes:
        """Read large memory in page-aligned chunks.

        Stubs often reject a read that crosses a page boundary if the next
        page is unmapped or has different permissions.  By never crossing a
        4 KiB boundary we avoid turning a partially readable page into a
        total failure.
        """
        result = bytearray()
        while length > 0:
            page_remaining = 0x1000 - (addr & 0xFFF)
            sz = min(self._max_chunk_size, length, page_remaining)
            data = self._send_raw(f'm{addr:x},{sz:x}')
            if not data or data.startswith(b'E'):
                break
            try:
                chunk = bytes.fromhex(data.decode())
            except (ValueError, UnicodeDecodeError):
                break
            result.extend(chunk)
            if len(chunk) < sz:
                break
            addr += sz
            length -= sz
        return bytes(result)

    def dump_phys_to_file(self, phys_addr: int, length: int,
                          filepath: str, progress_cb=None) -> int:
        self.phys_mode()
        try:
            with open(filepath, 'wb') as f:
                def _writer(data: bytes):
                    f.write(data)
                return self.read_phys_memory_safe(phys_addr, length, _writer,
                                                   progress_cb=progress_cb)
        finally:
            self.virt_mode()

    def read_phys_memory_safe(self, start: int, length: int, writer,
                              chunk_size: int = 0x10000,
                              progress_cb=None) -> int:
        """Reliable physical memory bulk reader using synchronous reads.

        Simple synchronous reading with no pipelining.  This is much safer
        on stubs whose ack-mode pipeline handling is fragile (the
        QEMU/VMware gdbstub used here returns duplicate or zero responses
        when more than one request is in flight).  The cost is lower
        throughput, but the data is correct.
        """
        chunk_size = max(PAGE_SIZE, chunk_size)
        written = 0
        pos = start
        remain = length
        next_progress = chunk_size
        zero_filled = 0
        while remain > 0:
            sz = min(chunk_size, remain)
            data = self.read_memory(pos, sz)
            if len(data) < sz:
                print(f"\n    WARNING: short read at PA 0x{pos:x}: "
                      f"got {len(data)}/{sz} bytes")
                # Retry the missing tail page-by-page to recover what we can.
                recovered = bytearray(data)
                tail = pos + len(data)
                remain_tail = sz - len(data)
                while remain_tail > 0:
                    page_remaining = PAGE_SIZE - (tail & (PAGE_SIZE - 1))
                    piece = min(remain_tail, page_remaining)
                    try:
                        retry = self.read_memory(tail, piece)
                    except Exception:
                        retry = b''
                    if len(retry) == piece:
                        recovered.extend(retry)
                    else:
                        print(f"      zero-filling {piece} bytes at PA 0x{tail:x}")
                        recovered.extend(b'\x00' * piece)
                        zero_filled += piece
                    tail += piece
                    remain_tail -= piece
                data = bytes(recovered)
                if zero_filled >= chunk_size:
                    # Catastrophic: entire chunk unreadable; the stub may be dead.
                    raise GdbError(
                        f"Unable to read any physical memory at PA 0x{pos:x}; "
                        f"the stub may have disconnected or switched out of "
                        f"physical memory mode.")
            writer(data)
            pos += sz
            remain -= sz
            written += sz
            if progress_cb and written >= next_progress:
                progress_cb(written)
                next_progress += chunk_size
        if zero_filled:
            print(f"\n    WARNING: {zero_filled} bytes zero-filled (unreadable)")
        if progress_cb:
            progress_cb(written)
        return written




    def read_dword(self, addr: int) -> int:
        d = self.read_memory(addr, 4)
        return struct.unpack('<I', d)[0] if len(d) >= 4 else 0

    def read_qword(self, addr: int) -> int:
        d = self.read_memory(addr, 8)
        return struct.unpack('<Q', d)[0] if len(d) >= 8 else 0

    def read_ptr(self, addr: int) -> int:
        if self.arch == 'x86':
            return self.read_dword(addr)
        return self.read_qword(addr)

    def read_string(self, addr: int, maxlen=512) -> str:
        data = self.read_memory(addr, maxlen)
        nul = data.find(b'\x00')
        if nul >= 0:
            data = data[:nul]
        return data.decode('ascii', errors='replace')

    # ═══ monitor commands (qRcmd) ═══════════════════════════════

    def monitor(self, cmd: str) -> str:
        """Send a monitor command. Handles O-prefixed console output."""
        hexcmd = cmd.encode('ascii').hex()
        result = bytearray()

        resp = self._send_raw(f'qRcmd,{hexcmd}')

        while True:
            if resp == b'OK':
                break
            if resp.startswith(b'O'):
                try:
                    decoded = bytes.fromhex(resp[1:].decode())
                    result.extend(decoded)
                except ValueError:
                    pass
                # Read next packet without sending a new command
                resp = self._read_next_packet()
            elif resp.startswith(b'E'):
                break
            else:
                try:
                    decoded = bytes.fromhex(resp.decode())
                    result.extend(decoded)
                except ValueError:
                    break
                break

        return result.decode('ascii', errors='replace').strip()

    def _read_next_packet(self) -> bytes:
        """Read the next RSP packet from stream without sending."""
        while True:
            c = self._recv1()
            if c == b'$':
                return self._read_packet_body()
            elif c == b'+':
                continue

    # ═══ physical / virtual memory mode ════════════════════════

    def phys_mode(self):
        """Switch to physical memory mode."""
        self.monitor('phys')

    def virt_mode(self):
        """Switch to virtual memory mode."""
        self.monitor('virt')

    # ═══ CR3 ════════════════════════════════════════════════════

    def get_cr3(self) -> int:
        """Read CR3 via monitor 'r cr3'."""
        try:
            r = self.monitor('r cr3')
            m = re.search(r'cr3\s*=\s*(0x[0-9a-fA-F]+)', r)
            if m:
                return int(m.group(1), 16)
        except Exception:
            pass
        return 0

    # ═══ kernel SharedUserData (KUSER_SHARED_DATA) ═══════════════

    _KUSER_SHARED_DATA = 0xFFFFF78000000000

    def read_kuser_shared(self) -> Dict[str, int]:
        """Read frequently used fields from KUSER_SHARED_DATA.

        Returns a dict with system_time, system_up_time, product_type,
        suite_mask, major_version, minor_version.  Missing/unreadable
        fields default to 0.
        """
        result = {
            'system_time': 0,
            'system_up_time': 0,
            'product_type': 0,
            'suite_mask': 0,
            'major_version': 0,
            'minor_version': 0,
        }
        base = self._KUSER_SHARED_DATA
        try:
            data = self.read_memory(base, 0x280)
            if len(data) >= 0x18 + 8:
                result['system_time'] = struct.unpack_from('<Q', data, 0x14)[0]
            if len(data) >= 0x10:
                result['system_up_time'] = struct.unpack_from('<Q', data, 0x08)[0]
            if len(data) >= 0x268:
                result['product_type'] = struct.unpack_from('<I', data, 0x264)[0]
            if len(data) >= 0x2D4:
                result['suite_mask'] = struct.unpack_from('<I', data, 0x2D0)[0]
            if len(data) >= 0x274:
                result['major_version'] = struct.unpack_from('<I', data, 0x26C)[0]
                result['minor_version'] = struct.unpack_from('<I', data, 0x270)[0]
        except Exception:
            pass
        return result


if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8864
    with GdbClient(host, port) as gdb:
        print(f"Arch: {gdb.arch}  Ptr: {gdb.reg_size}B")
        regs = gdb.read_all_regs_dict()
        for n, v in regs.items():
            print(f"  {n:8s} = 0x{v:016x}")
        cr3 = gdb.get_cr3()
        print(f"  CR3      = 0x{cr3:x}")
