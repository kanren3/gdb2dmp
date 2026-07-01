#!/usr/bin/env python3
"""
gdb2dmp — Convert a live Windows VM (via GDB stub) to a crash dump file.

Usage:
  python gdb2dmp.py -o bsod.dmp --target 127.0.0.1:8864

All kernel symbols are auto-detected via CR3 page-table walk and
PE export / KDBG scanning.
"""

import argparse
import os
import struct
import sys
import time as _time

from gdb_protocol import GdbClient, GdbConnectionError
from kernel_reader import (
    detect_kernel_base,
    discover_kernel,
    discover_physical_memory,
    read_context,
)
from dump_builder import DumpBuilder
from structs import PAGE_SIZE

def main():
    p = argparse.ArgumentParser(description='Live Windows VM -> crash dump via GDB stub')
    p.add_argument('-o', '--output', required=True, help='Output .dmp file')
    p.add_argument('--target', required=True, help='GDB stub host:port')
    args = p.parse_args()

    host, _, port_str = args.target.partition(':')
    port = int(port_str)

    print(f"[*] Connecting to {host}:{port} ...")
    try:
        gdb = GdbClient(host, port, timeout=30)
        gdb.connect()
    except (GdbConnectionError, ConnectionRefusedError, OSError) as e:
        sys.exit(f"ERROR: cannot connect: {e}")
    print(f"[*] Connected.  Arch: {gdb.arch}  Ptr: {gdb.reg_size}B")

    gdb.negotiate_features()

    try:
        # -- 1. kernel base --
        print("[*] Auto-detecting kernel base ...")
        kernel_base = detect_kernel_base(gdb)
        print(f"    kernel base = 0x{kernel_base:x}")

        # -- 2. kernel info --
        info = discover_kernel(gdb, kernel_base)

        # -- 3. physical memory --
        print("[*] Discovering physical memory layout ...")
        phys_mem = discover_physical_memory(gdb, info)
        info.physical_memory = phys_mem
        mb = phys_mem.NumberOfPages * PAGE_SIZE // (1024 * 1024)
        print(f"    {phys_mem.NumberOfRuns} run(s), "
              f"{phys_mem.NumberOfPages} pages ({mb} MB)")


        # ── 4. CPU context ──
        print("[*] Reading CPU context ...")
        ctx = read_context(gdb, gdb.arch)

        # ── 4.5 OS version / shared data (best effort) ──
        kuser = gdb.read_kuser_shared()
        # dbgeng uses the dump header version pair to decide whether the
        # target uses 64-bit kernel debugger-data APIs.  For x64 full dumps
        # this must be (DUMP_MAJOR_VERSION, NtBuildNumber).
        if gdb.arch == 'x86':
            if kuser.get('major_version'):
                info.major_version = kuser['major_version']
                info.minor_version = kuser['minor_version']
        else:
            info.major_version = 0x0F
            info.minor_version = info.build_number or 0
        info.system_time = kuser.get('system_time', 0)
        info.system_up_time = kuser.get('system_up_time', 0)
        info.product_type = kuser.get('product_type', 0)
        info.suite_mask = kuser.get('suite_mask', 0)

        # ── 5. build dump header ──
        print(f"[*] Writing dump header to {args.output} ...")
        with DumpBuilder(info, args.output) as builder:
            builder.set_context(ctx)
            builder.build()

            # Quick sanity check: read back the KdDebuggerDataBlock field.
            with open(args.output, 'rb') as hf:
                hdr = hf.read(0x88)
                if len(hdr) >= 0x88:
                    kdbg_hdr = struct.unpack_from('<Q', hdr, 0x80)[0]
                    print(f"    Header KdDebuggerDataBlock = 0x{kdbg_hdr:x}")
                    if not kdbg_hdr:
                        print("    WARNING: KdDebuggerDataBlock is 0x0 in dump header")
            # ── 6. dump physical memory via RSP ──
            total_mb = phys_mem.NumberOfPages * PAGE_SIZE // (1024*1024)
            print(f"[*] Dumping {total_mb} MB physical memory via RSP ...")

            chunk_size = 0x10000
            # The probe and kernel discovery leave the stub in virtual mode.
            # The dump body must be read from physical addresses.
            print("    Switching stub to physical memory mode ...")
            gdb.phys_mode()
            print(f"    Dump body chunk size: {chunk_size} bytes (safe synchronous reads)")

            overall_written = 0
            total_bytes = phys_mem.NumberOfPages * PAGE_SIZE
            _t_start = _time.time()
            for run_idx, run in enumerate(phys_mem.Runs):
                pa_start = run.BasePage * PAGE_SIZE
                pa_size = run.PageCount * PAGE_SIZE
                run_mb = pa_size // (1024*1024)
                _t_run = _time.time()
                print(f"  Run {run_idx}: 0x{pa_start:x} ({run_mb} MB)")

                def prog(written):
                    total_w = overall_written + written
                    pct = total_w * 100 // total_bytes
                    mb = total_w // (1024*1024)
                    elapsed = _time.time() - _t_start
                    speed = total_w / elapsed / (1024*1024) if elapsed > 0 else 0
                    print(f"\r    {pct:>2}%  {mb}/{total_mb} MB  {elapsed:.0f}s  {speed:.1f} MB/s    ",
                          end='', flush=True)

                written = gdb.read_phys_memory_safe(
                    pa_start, pa_size, builder,
                    chunk_size=chunk_size,
                    progress_cb=prog)
                overall_written += written
                _run_s = _time.time() - _t_run
                print(f"\r  Run {run_idx} done: {_run_s:.0f}s")

            # Restore virtual mode so the target can be debugged normally
            # after we disconnect.
            try:
                gdb.virt_mode()
            except Exception:
                pass

        dump_size = os.path.getsize(args.output)
        total_mb = dump_size // (1024*1024)
        print(f"[*] Done: {args.output}  ({total_mb} MB)")
        print(f"[*] Analyze with:  windbg -z {args.output}")

    except Exception as e:
        import traceback
        with open('gdb2dmp_error.log', 'w') as ef:
            ef.write(f"ERROR: {e}\n")
            traceback.print_exc(file=ef)
        sys.exit(f"ERROR: {e}")
    finally:
        gdb.close()


if __name__ == '__main__':
    main()
