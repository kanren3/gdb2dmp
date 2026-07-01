"""
Windows crash dump file builder.

Constructs a valid .dmp file from kernel data and physical memory dumps.
"""

import struct
import time
from typing import Optional, BinaryIO

from structs import (
    PAGE_SIZE,
    DUMP_SIGNATURE32, DUMP_SIGNATURE64,
    DUMP_VALID_DUMP32, DUMP_VALID_DUMP64,
    DumpType,
    IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64,
    DUMP_HEADER64_SIZE,
    DH64_SIGNATURE, DH64_VALID_DUMP, DH64_MAJOR_VERSION, DH64_MINOR_VERSION,
    DH64_DIRECTORY_TABLE_BASE, DH64_PFN_DATA_BASE,
    DH64_PS_LOADED_MODULE_LIST, DH64_PS_ACTIVE_PROCESS_HEAD,
    DH64_MACHINE_IMAGE_TYPE, DH64_NUMBER_PROCESSORS, DH64_BUGCHECK_CODE,
    DH64_BUGCHECK_PARAMETER1, DH64_BUGCHECK_PARAMETER2,
    DH64_BUGCHECK_PARAMETER3, DH64_BUGCHECK_PARAMETER4,
    DH64_VERSION_USER, DH64_KD_DEBUGGER_DATA_BLOCK,
    DH64_PHYSICAL_MEMORY_BLOCK, DH64_CONTEXT_RECORD, DH64_EXCEPTION,
    DH64_DUMP_TYPE, DH64_REQUIRED_DUMP_SPACE, DH64_SYSTEM_TIME,
    DH64_COMMENT, DH64_SYSTEM_UP_TIME, DH64_MINI_DUMP_FIELDS,
    DH64_SECONDARY_DATA_STATE, DH64_PRODUCT_TYPE, DH64_SUITE_MASK,
    DH64_WRITER_STATUS, DH64_KD_SECONDARY_VERSION,
)


class DumpBuilder:
    """Build a Windows crash dump file."""

    def __init__(self, info, output_path: str):
        self.info = info
        self.output_path = output_path
        self.is64 = info.reg_size == 8
        self._f: Optional[BinaryIO] = None
        self._bytes_written = 0
        self._context_data = b''

    def build(self):
        header_size = DUMP_HEADER64_SIZE if self.is64 else PAGE_SIZE
        self._f = open(self.output_path, 'wb')
        header = self._build_header()
        if len(header) < header_size:
            header += b'\x00' * (header_size - len(header))
        self._f.write(header)
        self._bytes_written = header_size

    def _build_header(self) -> bytes:
        info = self.info
        header_size = DUMP_HEADER64_SIZE if self.is64 else PAGE_SIZE
        buf = bytearray(header_size)
        sig = DUMP_SIGNATURE64 if self.is64 else DUMP_SIGNATURE32
        valid = DUMP_VALID_DUMP64 if self.is64 else DUMP_VALID_DUMP32

        if self.is64:
            self._write_header64(buf, sig, valid)
        else:
            self._write_header32(buf, sig, valid)
        return bytes(buf)

    def _write_header32(self, buf, sig, valid):
        info = self.info
        for i in range(0, 4096, 4):
            struct.pack_into('<I', buf, i, sig)
        p = 0
        struct.pack_into('<I', buf, p, sig); p += 4
        struct.pack_into('<I', buf, p, valid); p += 4
        struct.pack_into('<I', buf, p, info.major_version); p += 4
        struct.pack_into('<I', buf, p, info.minor_version); p += 4
        struct.pack_into('<I', buf, p, info.dtb & 0xFFFFFFFF); p += 4
        struct.pack_into('<I', buf, p, info.pfn_database & 0xFFFFFFFF); p += 4
        struct.pack_into('<I', buf, p, info.ps_loaded_module_list & 0xFFFFFFFF); p += 4
        struct.pack_into('<I', buf, p, info.ps_active_process_head & 0xFFFFFFFF); p += 4
        struct.pack_into('<I', buf, p, IMAGE_FILE_MACHINE_I386); p += 4
        struct.pack_into('<I', buf, p, getattr(info, 'number_processors', 1)); p += 4  # NumberProcessors
        struct.pack_into('<I', buf, p, 0xE2); p += 4  # BugCheckCode
        for _ in range(4):
            struct.pack_into('<I', buf, p, 0); p += 4
        ver = b"gdb2dmp"
        buf[p:p + len(ver)] = ver; p = 92
        p = 100
        pm = info.physical_memory
        if pm:
            struct.pack_into('<I', buf, p, pm.NumberOfRuns); p += 4
            struct.pack_into('<I', buf, p, pm.NumberOfPages); p += 4
            for r in pm.Runs:
                struct.pack_into('<I', buf, p, r.BasePage & 0xFFFFFFFF); p += 4
                struct.pack_into('<I', buf, p, r.PageCount & 0xFFFFFFFF); p += 4
        p = 800
        if self._context_data:
            buf[p:p + len(self._context_data)] = self._context_data
        p = 2000
        struct.pack_into('<I', buf, p, 0x80000003); p += 4
        struct.pack_into('<I', buf, p, 1); p += 4
        struct.pack_into('<I', buf, p, 0); p += 4
        struct.pack_into('<I', buf, p, 0); p += 4
        struct.pack_into('<I', buf, p, 0); p += 4
        p += 15 * 4
        struct.pack_into('<I', buf, 3976, DumpType.DUMP_TYPE_FULL)
        struct.pack_into('<Q', buf, 4000, 0)
        ft = int(time.time() * 10000000) + 116444736000000000
        struct.pack_into('<I', buf, 4032, ft & 0xFFFFFFFF)
        struct.pack_into('<I', buf, 4036, (ft >> 32) & 0xFFFFFFFF)

    def _write_header64(self, buf, sig, valid):
        info = self.info
        # Fill the entire 8KB header with the PAGE signature first.
        for i in range(0, len(buf), 4):
            struct.pack_into('<I', buf, i, sig)

        # Fixed header fields (matches Win7 x64 _DUMP_HEADER64)
        struct.pack_into('<I', buf, DH64_SIGNATURE, sig)
        struct.pack_into('<I', buf, DH64_VALID_DUMP, valid)
        struct.pack_into('<I', buf, DH64_MAJOR_VERSION, info.major_version)
        struct.pack_into('<I', buf, DH64_MINOR_VERSION, info.minor_version)
        struct.pack_into('<Q', buf, DH64_DIRECTORY_TABLE_BASE, info.dtb)
        struct.pack_into('<Q', buf, DH64_PFN_DATA_BASE, info.pfn_database)
        struct.pack_into('<Q', buf, DH64_PS_LOADED_MODULE_LIST, info.ps_loaded_module_list)
        struct.pack_into('<Q', buf, DH64_PS_ACTIVE_PROCESS_HEAD, info.ps_active_process_head)
        struct.pack_into('<I', buf, DH64_MACHINE_IMAGE_TYPE, IMAGE_FILE_MACHINE_AMD64)
        struct.pack_into('<I', buf, DH64_NUMBER_PROCESSORS, getattr(info, 'number_processors', 1))
        struct.pack_into('<I', buf, DH64_BUGCHECK_CODE, 0xE2)
        struct.pack_into('<Q', buf, DH64_BUGCHECK_PARAMETER1, 0)
        struct.pack_into('<Q', buf, DH64_BUGCHECK_PARAMETER2, 0)
        struct.pack_into('<Q', buf, DH64_BUGCHECK_PARAMETER3, 0)
        struct.pack_into('<Q', buf, DH64_BUGCHECK_PARAMETER4, 0)

        ver = b"gdb2dmp"
        buf[DH64_VERSION_USER:DH64_VERSION_USER + len(ver)] = ver

        struct.pack_into('<Q', buf, DH64_KD_DEBUGGER_DATA_BLOCK,
                         info.kd_debugger_data_block)

        # Physical memory descriptor (max 700 bytes at 0x88)
        pm = info.physical_memory
        if pm:
            # x64 _PHYSICAL_MEMORY_DESCRIPTOR:
            #   +0x00 NumberOfRuns  (Uint4B)
            #   +0x04 padding       (4 bytes)
            #   +0x08 NumberOfPages (Uint8B)
            #   +0x10 Run[i].BasePage  (Uint8B)
            #   +0x18 Run[i].PageCount (Uint8B)
            base = DH64_PHYSICAL_MEMORY_BLOCK
            struct.pack_into('<I', buf, base, pm.NumberOfRuns)
            struct.pack_into('<Q', buf, base + 8, pm.NumberOfPages)
            p = base + 0x10
            for r in pm.Runs:
                struct.pack_into('<Q', buf, p, r.BasePage); p += 8
                struct.pack_into('<Q', buf, p, r.PageCount); p += 8

        # CONTEXT record (3000 bytes at 0x348)
        if self._context_data:
            ctx = self._context_data[:3000]
            buf[DH64_CONTEXT_RECORD:DH64_CONTEXT_RECORD + len(ctx)] = ctx

        # EXCEPTION_RECORD64 at 0x0f00
        p = DH64_EXCEPTION
        struct.pack_into('<I', buf, p, 0x80000003); p += 4  # ExceptionCode
        struct.pack_into('<I', buf, p, 1); p += 4           # ExceptionFlags
        struct.pack_into('<Q', buf, p, 0); p += 8           # ExceptionRecord
        struct.pack_into('<Q', buf, p, 0); p += 8           # ExceptionAddress
        struct.pack_into('<I', buf, p, 0); p += 4           # NumberParameters
        p += 4                                              # padding
        for _ in range(15):
            struct.pack_into('<Q', buf, p, 0); p += 8       # ExceptionInformation

        struct.pack_into('<I', buf, DH64_DUMP_TYPE, DumpType.DUMP_TYPE_FULL)
        num_pages = pm.NumberOfPages if pm else 0
        struct.pack_into('<Q', buf, DH64_REQUIRED_DUMP_SPACE,
                         DUMP_HEADER64_SIZE + num_pages * PAGE_SIZE)

        # SystemTime / SystemUpTime from kernel SharedUserData if available;
        # otherwise fall back to local time / zero.
        st = getattr(info, 'system_time', 0)
        if st == 0:
            st = int(time.time() * 10000000) + 116444736000000000
        ut = getattr(info, 'system_up_time', 0)
        pt = getattr(info, 'product_type', 0)
        sm = getattr(info, 'suite_mask', 0)

        struct.pack_into('<Q', buf, DH64_SYSTEM_TIME, st)
        struct.pack_into('<Q', buf, DH64_SYSTEM_UP_TIME, ut)
        struct.pack_into('<I', buf, DH64_MINI_DUMP_FIELDS, 0)
        struct.pack_into('<I', buf, DH64_SECONDARY_DATA_STATE, 0)
        struct.pack_into('<I', buf, DH64_PRODUCT_TYPE, pt)
        struct.pack_into('<I', buf, DH64_SUITE_MASK, sm)
        struct.pack_into('<I', buf, DH64_WRITER_STATUS, 0)
        struct.pack_into('<B', buf, DH64_KD_SECONDARY_VERSION, 0)

    def set_context(self, ctx_bytes: bytes):
        self._context_data = ctx_bytes


    def write_physical_memory(self, phys_addr: int, data: bytes):
        if self._f:
            # Ensure we append at the logical end of the file.
            self._f.seek(self._bytes_written)
            self._f.write(data)
            self._bytes_written += len(data)


    def __call__(self, data: bytes):
        """Callable writer interface used by bulk readers."""
        self.write_physical_memory(0, data)

    def close(self):
        if self._f:
            self._f.close()
            self._f = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
