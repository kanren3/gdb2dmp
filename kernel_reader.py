"""
Windows kernel reader — RSP dump + local scan.

Strategy:
  1. RSP client reads CR3 + RIP, walks page table to find kernel PA hint
  2. RSP dumps 64MB physical around hint to temp file (bulk m-packets)
  3. Scan temp file locally for MZ+PE+POOLCODE (instant, no round-trips)
"""

import struct
import os
import tempfile
from typing import Optional, Dict, List, Tuple

from gdb_protocol import GdbClient, GdbError
from structs import (
    PAGE_SIZE,
    PhysicalMemoryRun, PhysicalMemoryDescriptor,
)

POOLCODE_QWORD = 0x45444F434C4F4F50   # "POOLCODE" as LE qword
KDBG_TAG = 0x4742444B                 # "KDBG" as LE dword


class KernelInfo:
    __slots__ = (
        'kernel_base', 'kernel_size', 'reg_size', 'arch', 'dtb',
        'ps_loaded_module_list', 'ps_active_process_head',
        'pfn_database', 'kd_debugger_data_block',
        'major_version', 'minor_version', 'build_number',
        'system_time', 'system_up_time', 'product_type', 'suite_mask',
        'physical_memory', 'number_processors',
    )

    def __init__(self, kernel_base=0, kernel_size=0, reg_size=0, arch='',
                 dtb=0, ps_loaded_module_list=0, ps_active_process_head=0,
                 pfn_database=0, kd_debugger_data_block=0,
                 major_version=6, minor_version=1,
                 build_number=7601, physical_memory=None):
        self.kernel_base = kernel_base
        self.kernel_size = kernel_size
        self.reg_size = reg_size
        self.arch = arch
        self.dtb = dtb
        self.ps_loaded_module_list = ps_loaded_module_list
        self.ps_active_process_head = ps_active_process_head
        self.pfn_database = pfn_database
        self.kd_debugger_data_block = kd_debugger_data_block
        self.major_version = major_version
        self.minor_version = minor_version
        self.build_number = build_number
        self.system_time = 0
        self.system_up_time = 0
        self.product_type = 0
        self.suite_mask = 0
        self.physical_memory = physical_memory
        self.number_processors = 1


# ═══════════════════════════════════════════════════════════════
#  detect_kernel_base — GDB dump + local scan
# ═══════════════════════════════════════════════════════════════

def detect_kernel_base(gdb: GdbClient) -> int:
    """Auto-detect kernel base.

    Strategy:
      1. Probe likely kernel base VAs near RIP by page-table walk +
         MZ/PE signature check (fast, no bulk dump).
      2. If that fails, fall back to dumping physical memory around the
         RIP PA hint and scanning for MZ+PE+POOLCODE.
    """
    cr3 = gdb.get_cr3()
    if not cr3:
        raise GdbError("Cannot read CR3 via monitor 'r cr3'")
    print(f"    CR3 = 0x{cr3:x}")

    regs = gdb.read_all_regs_dict()
    rip = regs.get('rip', 0)
    if not rip or (rip >> 48) != 0xFFFF:
        raise GdbError("RIP is not in kernel space, cannot use as hint")
    print(f"    RIP = 0x{rip:x}")

    # ── Phase 1: fast candidate scan near RIP in virtual space ──
    print("    Probing kernel base VA candidates near RIP ...")
    kernel_va = _probe_kernel_base_candidates(gdb, cr3, rip)
    if kernel_va:
        return kernel_va

    # ── Phase 2: fallback to physical dump + scan ──
    print("    Candidate scan failed, falling back to physical dump scan ...")
    return _detect_kernel_base_by_dump(gdb, cr3, rip)


def _probe_kernel_base_candidates(gdb: GdbClient, cr3: int, rip: int,
                                   radius: int = 0x80000000,
                                   step: int = 0x200000) -> int:
    """Search 2MB-aligned kernel base VAs near RIP.

    Windows x64 ntoskrnl is loaded at a 2MB-aligned VA below RIP in
    canonical kernel space.  We translate candidate VAs to PAs and look
    for a valid MZ+PE header.  This avoids dumping large physical ranges.

    Returns kernel VA or 0 if not found.
    """
    gdb.phys_mode()
    try:
        # Search backwards from RIP first (kernel base is always <= RIP).
        end = rip & ~(step - 1)
        start = max(0xFFFF000000000000, end - radius) & ~(step - 1)
        for va in range(end, start - 1, -step):
            if (va >> 48) != 0xFFFF:
                continue
            pa = _va_to_pa(gdb, cr3, va)
            if not pa:
                continue
            if not _is_kernel_pe_header(gdb, pa):
                continue
            print(f"    MZ+PE at VA 0x{va:x} (PA 0x{pa:x})")
            return va

        # Rarely, RIP might be in a very early stub; search forwards too.
        fwd_end = min(0xFFFFFFFFFFFF0000, end + radius) & ~(step - 1)
        for va in range(end + step, fwd_end + 1, step):
            if (va >> 48) != 0xFFFF:
                continue
            pa = _va_to_pa(gdb, cr3, va)
            if not pa:
                continue
            if not _is_kernel_pe_header(gdb, pa):
                continue
            print(f"    MZ+PE at VA 0x{va:x} (PA 0x{pa:x})")
            return va
    finally:
        gdb.virt_mode()
    return 0


def _is_kernel_pe_header(gdb: GdbClient, pa: int) -> bool:
    """Check whether physical address contains a valid MZ+PE header.

    Additionally scans the first 0x800 bytes for the POOLCODE qword to
    reduce false positives on non-kernel PE images.
    """
    data = gdb.read_memory(pa, 2)
    if data != b'MZ':
        return False
    e_lfanew_data = gdb.read_memory(pa + 0x3C, 4)
    if len(e_lfanew_data) < 4:
        return False
    e_lfanew = struct.unpack('<I', e_lfanew_data)[0]
    if e_lfanew < 64 or e_lfanew > 0x400:
        return False
    pe_sig = gdb.read_memory(pa + e_lfanew, 4)
    if len(pe_sig) < 4:
        return False
    if struct.unpack('<I', pe_sig)[0] != 0x00004550:
        return False
    # Look for POOLCODE in the first 0x400 bytes of the image.
    # (Keep the window small so restrictive stubs don't reject the read.)
    hdr = gdb.read_memory(pa, 0x400)
    if len(hdr) < 8:
        return False
    for o in range(0, len(hdr) - 8, 8):
        if struct.unpack_from('<Q', hdr, o)[0] == POOLCODE_QWORD:
            return True
    return False


def _detect_kernel_base_by_dump(gdb: GdbClient, cr3: int, rip: int) -> int:
    """Fallback: dump physical memory around RIP PA and scan for kernel."""
    gdb.phys_mode()
    try:
        rip_pa = _va_to_pa(gdb, cr3, rip)
    finally:
        gdb.virt_mode()

    if not rip_pa:
        raise GdbError("Cannot translate RIP to physical address")

    # 2MB-align the physical address, then dump 512MB centered on it
    hint_pa = rip_pa & ~0x1FFFFF
    dump_start = max(0, hint_pa - 128 * 0x200000)   # 256MB before
    dump_end = hint_pa + 128 * 0x200000              # 256MB after
    dump_size = dump_end - dump_start

    print(f"    RIP PA = 0x{rip_pa:x}")
    print(f"    dump range: 0x{dump_start:x} – 0x{dump_end:x} ({dump_size // 0x100000} MB)")

    tmpfile = os.path.join(tempfile.gettempdir(), 'gdb2dmp_kernel_scan.bin')
    print(f"    dumping {dump_size // 0x100000} MB via RSP ...")
    gdb.phys_mode()
    try:
        gdb.dump_phys_to_file(dump_start, dump_size, tmpfile)
    finally:
        gdb.virt_mode()

    if not os.path.exists(tmpfile) or os.path.getsize(tmpfile) == 0:
        raise GdbError("RSP dump failed — empty file")

    fsize = os.path.getsize(tmpfile)
    print(f"    dumped {fsize // 0x100000} MB")

    kernel_pa = _scan_local_file(tmpfile, dump_start)
    if not kernel_pa:
        os.unlink(tmpfile)
        raise GdbError("Kernel not found in dumped physical memory")

    gdb.phys_mode()
    try:
        kernel_va = _pa_to_kernel_va_fast(gdb, cr3, kernel_pa)
    finally:
        gdb.virt_mode()

    os.unlink(tmpfile)
    if not kernel_va:
        raise GdbError(f"Cannot translate kernel PA 0x{kernel_pa:x} to VA")
    return kernel_va


def _va_to_pa(gdb: GdbClient, cr3: int, va: int) -> int:
    """Walk x64 page tables in phys mode. Returns physical address of va."""
    pml4_idx = (va >> 39) & 0x1FF
    pdpt_idx = (va >> 30) & 0x1FF
    pd_idx   = (va >> 21) & 0x1FF
    pt_idx   = (va >> 12) & 0x1FF
    page_off = va & 0xFFF

    pml4_pa = cr3 & ~0xFFF

    data = gdb.read_memory(pml4_pa + pml4_idx * 8, 8)
    if len(data) < 8: return 0
    pml4e = struct.unpack('<Q', data)[0]
    if not (pml4e & 1): return 0

    data = gdb.read_memory((pml4e & 0x000FFFFFFFFFF000) + pdpt_idx * 8, 8)
    if len(data) < 8: return 0
    pdpte = struct.unpack('<Q', data)[0]
    if not (pdpte & 1): return 0

    pd_pa = pdpte & 0x000FFFFFFFFFF000
    data = gdb.read_memory(pd_pa + pd_idx * 8, 8)
    if len(data) < 8: return 0
    pde = struct.unpack('<Q', data)[0]
    if not (pde & 1): return 0

    if pde & 0x80:  # 2MB large page
        page_pa = pde & 0x000FFFFFFFFFF000
        return page_pa + (va & 0x1FFFFF)

    # 4KB page
    pt_pa = pde & 0x000FFFFFFFFFF000
    data = gdb.read_memory(pt_pa + pt_idx * 8, 8)
    if len(data) < 8: return 0
    pte = struct.unpack('<Q', data)[0]
    if not (pte & 1): return 0
    return (pte & 0x000FFFFFFFFFF000) + page_off


def _pa_to_kernel_va_fast(gdb: GdbClient, cr3: int, pa: int) -> int:
    """Translate physical address to kernel VA by walking page tables.
    Must be called in phys_mode."""
    pml4_pa = cr3 & ~0xFFF
    pml4_entries = _batch_read_pte(gdb, pml4_pa, 512)
    for pml4_idx in range(256, 512):
        pml4e = pml4_entries[pml4_idx]
        if not (pml4e & 1):
            continue
        pdpt_pa = pml4e & 0x000FFFFFFFFFF000
        va_pml4 = (0xFFFF << 48) | (pml4_idx << 39)
        pdpt_entries = _batch_read_pte(gdb, pdpt_pa, 512)
        for pdpt_idx in range(512):
            pdpte = pdpt_entries[pdpt_idx]
            if not (pdpte & 1):
                continue
            pd_pa = pdpte & 0x000FFFFFFFFFF000
            pd_entries = _batch_read_pte(gdb, pd_pa, 512)
            for pd_idx in range(512):
                pde = pd_entries[pd_idx]
                if not (pde & 1):
                    continue
                if pde & 0x80:  # 2MB page
                    page_pa = pde & 0x000FFFFFFFFFF000
                    if page_pa <= pa < page_pa + 0x200000:
                        va = va_pml4 + (pdpt_idx << 30) + (pd_idx << 21)
                        return va + (pa - page_pa)
                else:  # 4KB page
                    pt_pa = pde & 0x000FFFFFFFFFF000
                    pt_entries = _batch_read_pte(gdb, pt_pa, 512)
                    for pt_idx in range(512):
                        pte = pt_entries[pt_idx]
                        if not (pte & 1):
                            continue
                        page_pa = pte & 0x000FFFFFFFFFF000
                        if page_pa == (pa & ~0xFFF):
                            va = (va_pml4 + (pdpt_idx << 30) +
                                  (pd_idx << 21) + (pt_idx << 12))
                            return va + (pa & 0xFFF)
    return 0


def _scan_local_file(filepath: str, base_pa: int) -> int:
    """Scan dumped physical memory file for MZ+PE+POOLCODE.
    Returns physical address of kernel base, or 0."""
    CHUNK = 0x200000  # 2MB read chunks
    with open(filepath, 'rb') as f:
        offset = 0
        while True:
            data = f.read(CHUNK)
            if not data:
                break
            for off in range(0, len(data) - 0x800, PAGE_SIZE):
                if data[off:off+2] != b'MZ':
                    continue
                e_lfanew = struct.unpack_from('<I', data, off + 0x3C)[0]
                if e_lfanew < 64 or e_lfanew > 0x400:
                    continue
                if e_lfanew + 4 > len(data) - off:
                    continue
                if struct.unpack_from('<I', data, off + e_lfanew)[0] != 0x00004550:
                    continue
                scan_end = min(off + 0x800, len(data))
                for o in range(off, scan_end - 8, 8):
                    if struct.unpack_from('<Q', data, o)[0] == POOLCODE_QWORD:
                        pa = base_pa + offset + off
                        print(f"    MZ+PE+POOLCODE at PA 0x{pa:x}")
                        return pa
            offset += len(data)
    return 0


# ═══════════════════════════════════════════════════════════════
#  discover_kernel — fill KernelInfo after base is found
# ═══════════════════════════════════════════════════════════════

def _read_kernel_export(gdb: GdbClient, info: KernelInfo,
                        export_name: str, size: int = 4) -> bytes:
    """Read `size` bytes from a kernel PE export (by name).

    Must be called in phys mode. The kernel image is assumed to be loaded
    as one contiguous physical block, so RVAs map directly to kpa + RVA.
    """
    kbase = info.kernel_base
    kpa = _va_to_pa(gdb, info.dtb, kbase)
    if not kpa:
        return b''
    try:
        hdr = gdb.read_memory(kpa, 0x200)
        if len(hdr) < 0x100 or hdr[:2] != b'MZ':
            return b''
        e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
        opt_off = e_lfanew + 24
        exp_rva = struct.unpack_from('<I', hdr, opt_off + 0x70)[0]
        if not exp_rva:
            return b''
        expdir = gdb.read_memory(kpa + exp_rva, 40)
        if len(expdir) < 40:
            return b''
        num_names = struct.unpack_from('<I', expdir, 24)[0]
        addr_names = struct.unpack_from('<I', expdir, 32)[0]
        addr_ords = struct.unpack_from('<I', expdir, 36)[0]
        addr_funcs = struct.unpack_from('<I', expdir, 28)[0]
        if not num_names or not addr_names:
            return b''
        names_arr = gdb.read_memory(kpa + addr_names, num_names * 4)
        if len(names_arr) < num_names * 4:
            return b''
        ord_arr = gdb.read_memory(kpa + addr_ords, num_names * 2)
        if len(ord_arr) < num_names * 2:
            return b''
        name_rvas = [struct.unpack_from('<I', names_arr, i * 4)[0] for i in range(num_names)]
        min_rva = min(name_rvas)
        max_rva = max(name_rvas)
        region = gdb.read_memory(kpa + min_rva, min(max_rva - min_rva + 32, 0x10000))
        target = export_name.encode('ascii')
        for i in range(num_names):
            off = name_rvas[i] - min_rva
            if 0 <= off < len(region):
                end = region.find(b'\x00', off)
                if end < 0:
                    end = len(region)
                if region[off:end] == target:
                    ordinal = struct.unpack_from('<H', ord_arr, i * 2)[0]
                    funcs_arr = gdb.read_memory(kpa + addr_funcs, (ordinal + 1) * 4)
                    if len(funcs_arr) >= (ordinal + 1) * 4:
                        func_rva = struct.unpack_from('<I', funcs_arr, ordinal * 4)[0]
                        val = gdb.read_memory(kpa + func_rva, size)
                        if len(val) >= size:
                            return val[:size]
        return b''
    except Exception:
        return b''


def _read_nt_build_number(gdb: GdbClient, info: KernelInfo) -> int:
    """Read NtBuildNumber (exported ULONG) from the kernel PE export table."""
    val = _read_kernel_export(gdb, info, 'NtBuildNumber', 4)
    return struct.unpack_from('<I', val, 0)[0] & 0xFFFF if len(val) >= 4 else 0


def _read_ke_number_processors(gdb: GdbClient, info: KernelInfo) -> int:
    """Read KeNumberProcessors (exported UCHAR) from the kernel image."""
    val = _read_kernel_export(gdb, info, 'KeNumberProcessors', 1)
    if not val:
        return 1
    count = val[0]
    return count if 1 <= count <= 0x40 else 1


def discover_kernel(gdb: GdbClient, kernel_base: int,
                    dtb: int = 0,
                    ps_loaded_module_list: int = 0,
                    ps_active_process_head: int = 0,
                    pfn_database: int = 0,
                    build_number: int = 0) -> KernelInfo:
    """Fill KernelInfo. kernel_base is a physical address; we translate
    it to VA via the page table."""

    info = KernelInfo(
        reg_size=gdb.reg_size,
        arch=gdb.arch,
        dtb=dtb or gdb.get_cr3(),
        ps_loaded_module_list=ps_loaded_module_list,
        ps_active_process_head=ps_active_process_head,
        pfn_database=pfn_database,
        build_number=build_number,
    )

    # If kernel_base looks like a PA (from detect_kernel_base),
    # translate to VA via page table walk
    if kernel_base < 0x10000000000:  # looks like PA, not VA
        va = _pa_to_kernel_va(gdb, info.dtb, kernel_base)
        if va:
            info.kernel_base = va
        else:
            info.kernel_base = kernel_base  # fallback
    else:
        info.kernel_base = kernel_base

    # Read PE header in phys mode for kernel size
    gdb.phys_mode()
    try:
        pa = _va_to_pa(gdb, info.dtb, info.kernel_base)
        if pa:
            hdr = gdb.read_memory(pa, 480)
            if len(hdr) >= 0x100 and hdr[:2] == b'MZ':
                e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
                if e_lfanew + 80 <= len(hdr):
                    info.kernel_size = struct.unpack_from('<I', hdr, e_lfanew + 24 + 56)[0]

        # KDBG scan
        _kdbg_scan_phys(gdb, info)
        # NtBuildNumber from PE export table (if not already set)
        if not info.build_number:
            info.build_number = _read_nt_build_number(gdb, info)
        # Processor count from PE export table
        info.number_processors = _read_ke_number_processors(gdb, info)
    finally:
        gdb.virt_mode()

    print(f"    Kernel base (VA)     = 0x{info.kernel_base:x}")
    print(f"    Kernel size          = 0x{info.kernel_size:x}")
    print(f"    DTB (CR3)            = 0x{info.dtb:x}")
    print(f"    PsLoadedModuleList   = 0x{info.ps_loaded_module_list:x}")
    print(f"    PsActiveProcessHead  = 0x{info.ps_active_process_head:x}")
    print(f"    MmPfnDatabase        = 0x{info.pfn_database:x}")
    print(f"    KdDebuggerDataBlock  = 0x{info.kd_debugger_data_block:x}")
    print(f"    BuildNumber          = {info.build_number}")
    print(f"    NumberProcessors     = {info.number_processors}")

    if not info.kd_debugger_data_block:
        print("    WARNING: KdDebuggerDataBlock not found; dump may not load in WinDbg")

    return info


def _pa_to_kernel_va(gdb: GdbClient, cr3: int, pa: int) -> int:
    """Find the kernel VA that maps to physical address `pa`.

    Scans PML4 entries in kernel space (idx >= 256) for 2MB large pages
    that contain this physical address.
    """
    gdb.phys_mode()
    try:
        pml4_pa = cr3 & ~0xFFF
        pml4_entries = _batch_read_pte(gdb, pml4_pa, 512)

        for pml4_idx in range(256, 512):
            pml4e = pml4_entries[pml4_idx]
            if not (pml4e & 1):
                continue
            pdpt_pa = pml4e & 0x000FFFFFFFFFF000
            va_pml4 = (0xFFFF << 48) | (pml4_idx << 39)

            pdpt_entries = _batch_read_pte(gdb, pdpt_pa, 512)
            for pdpt_idx in range(512):
                pdpte = pdpt_entries[pdpt_idx]
                if not (pdpte & 1):
                    continue
                pd_pa = pdpte & 0x000FFFFFFFFFF000
                pd_entries = _batch_read_pte(gdb, pd_pa, 512)

                for pd_idx in range(512):
                    pde = pd_entries[pd_idx]
                    if not (pde & 1):
                        continue
                    if pde & 0x80:  # 2MB page
                        page_pa = pde & 0x000FFFFFFFFFF000
                        if page_pa <= pa < page_pa + 0x200000:
                            va = va_pml4 + (pdpt_idx << 30) + (pd_idx << 21)
                            return va + (pa - page_pa)
                    else:
                        # 4KB page
                        pt_pa = pde & 0x000FFFFFFFFFF000
                        pt_entries = _batch_read_pte(gdb, pt_pa, 512)
                        for pt_idx in range(512):
                            pte = pt_entries[pt_idx]
                            if not (pte & 1):
                                continue
                            page_pa = pte & 0x000FFFFFFFFFF000
                            if page_pa == (pa & ~0xFFF):
                                va = va_pml4 + (pdpt_idx << 30) + (pd_idx << 21) + (pt_idx << 12)
                                return va + (pa & 0xFFF)
    finally:
        gdb.virt_mode()
    return 0


def _batch_read_pte(gdb: GdbClient, pa: int, count: int) -> list:
    """Read `count` 8-byte PTEs.  60 entries per read (480 bytes)."""
    entries = [0] * count
    chunk = 60
    for start in range(0, count, chunk):
        n = min(chunk, count - start)
        data = gdb.read_memory(pa + start * 8, n * 8)
        if not data:
            continue
        for i in range(0, min(len(data), n * 8), 8):
            if i + 8 <= len(data):
                entries[start + i // 8] = struct.unpack_from('<Q', data, i)[0]
    return entries


# Offsets inside _KDDEBUGGER_DATA64 (Win7 x64, confirmed via IDA)
KDBG_KernBase = 0x18
KDBG_PsLoadedModuleList = 0x48
KDBG_PsActiveProcessHead = 0x50
KDBG_MmPfnDatabase = 0xC0
KDBG_KiBugcheckData = 0x88
KDBG_MmPhysicalMemoryBlock = 0x270


def _kdbg_scan_phys(gdb: GdbClient, info: KernelInfo):
    """Scan kernel .data section (in phys mode) for a valid KDBG block.

    The KDBG 'KDBG' tag is expected 16 bytes before the start of the
    _KDDEBUGGER_DATA64 structure.  We accept only candidates whose
    KernBase matches the detected kernel base and whose key pointers are
    non-zero kernel VAs.
    """
    base_va = info.kernel_base
    base_pa = _va_to_pa(gdb, info.dtb, base_va)
    if not base_pa:
        print("    KDBG scan: cannot translate kernel base to PA")
        return

    hdr = gdb.read_memory(base_pa, 480)
    if len(hdr) < 0x100:
        print("    KDBG scan: failed to read kernel PE header")
        return

    e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
    if e_lfanew + 24 > len(hdr):
        print(f"    KDBG scan: bad e_lfanew {e_lfanew}")
        return

    nt_sig = struct.unpack_from('<I', hdr, e_lfanew)[0]
    if nt_sig != 0x00004550:  # 'PE\0\0'
        print(f"    KDBG scan: invalid NT signature 0x{nt_sig:08x}")
        return

    opt_hdr_size = struct.unpack_from('<H', hdr, e_lfanew + 20)[0]
    num_sections = struct.unpack_from('<H', hdr, e_lfanew + 6)[0]
    sec_start = e_lfanew + 24 + opt_hdr_size

    # Read the full section table (most kernels have <32 sections).
    sec_table_size = num_sections * 40
    sec_data = gdb.read_memory(base_pa + sec_start, sec_table_size)
    if len(sec_data) < sec_table_size:
        print(f"    KDBG scan: short section table read {len(sec_data)}/{sec_table_size}")
        return

    data_va = data_sz = 0
    section_names = []
    for i in range(num_sections):
        s = sec_data[i*40 : (i+1)*40]
        name = s[:8].rstrip(b'\x00').decode('ascii', errors='replace')
        section_names.append(name)
        if name == '.data':
            data_va = struct.unpack_from('<I', s, 12)[0]
            data_sz = struct.unpack_from('<I', s, 8)[0] or struct.unpack_from('<I', s, 16)[0]

    print(f"    sections: {', '.join(section_names)}")

    if not data_va or data_sz == 0:
        print(f"    KDBG scan: .data section not found or empty (va={data_va:x} sz={data_sz:x})")
        # Fall back to scanning a region just after the headers.
        data_va = sec_start + sec_table_size
        data_sz = 0x100000
        print(f"    falling back to scan region VA=0x{data_va:x} size=0x{data_sz:x}")
    else:
        print(f"    .data: VA=0x{data_va:x} size=0x{data_sz:x}")

    data_pa = _va_to_pa(gdb, info.dtb, base_va + data_va)
    if not data_pa:
        print("    KDBG scan: cannot translate .data to PA")
        return

    def _is_kernel_va(va: int) -> bool:
        return va != 0 and (va >= 0xFFFF000000000000 or va >= 0x80000000)

    KDBG_STRUCT_SIZE = 0x280  # enough to reach MmPhysicalMemoryBlock at 0x270

    def _try_candidate(kdbg_va: int, candidate_pa: int) -> bool:
        # Read the full KDBG structure so all field offsets are accessible.
        full = gdb.read_memory(candidate_pa, KDBG_STRUCT_SIZE)
        if len(full) < KDBG_STRUCT_SIZE:
            print(f"    KDBG candidate at 0x{kdbg_va:x}: short read {len(full)} bytes")
            return False

        kern_base = struct.unpack_from('<Q', full, KDBG_KernBase)[0]
        plm = struct.unpack_from('<Q', full, KDBG_PsLoadedModuleList)[0]
        paph = struct.unpack_from('<Q', full, KDBG_PsActiveProcessHead)[0]
        pfn = struct.unpack_from('<Q', full, KDBG_MmPfnDatabase)[0]
        kibug = struct.unpack_from('<Q', full, KDBG_KiBugcheckData)[0]
        pmblock = struct.unpack_from('<Q', full, KDBG_MmPhysicalMemoryBlock)[0]

        if kern_base != base_va:
            return False
        if not (_is_kernel_va(plm) and _is_kernel_va(paph) and _is_kernel_va(pfn)
                and _is_kernel_va(kibug) and _is_kernel_va(pmblock)):
            print(f"    KDBG candidate at 0x{kdbg_va:x} rejected: bad pointers")
            return False

        if not info.ps_loaded_module_list:
            info.ps_loaded_module_list = plm
        if not info.ps_active_process_head:
            info.ps_active_process_head = paph
        if not info.pfn_database:
            info.pfn_database = pfn
        if not info.kd_debugger_data_block:
            info.kd_debugger_data_block = kdbg_va

        # Sanity check: can we read the same KDBG via virt mode?
        try:
            virt = gdb.read_memory(kdbg_va, 0x60)
            if len(virt) >= 0x60:
                v_kern = struct.unpack_from('<Q', virt, KDBG_KernBase)[0]
                v_plm = struct.unpack_from('<Q', virt, KDBG_PsLoadedModuleList)[0]
                if v_kern != kern_base or v_plm != plm:
                    print(f"    WARNING: KDBG phys/virt mismatch at 0x{kdbg_va:x}")
        except Exception:
            pass

        print(f"    KDBG found at VA 0x{kdbg_va:x}")
        print(f"      KernBase            = 0x{kern_base:x}")
        print(f"      PsLoadedModuleList  = 0x{plm:x}")
        print(f"      PsActiveProcessHead = 0x{paph:x}")
        print(f"      MmPfnDatabase       = 0x{pfn:x}")
        print(f"      KiBugcheckData      = 0x{kibug:x}")
        print(f"      MmPhysicalMemoryBlock = 0x{pmblock:x}")
        print(f"    KDBG raw hex (0x{kdbg_va:x}):")
        for row in range(0, KDBG_STRUCT_SIZE, 32):
            line = full[row:row+32]
            if len(line) < 32:
                line = line + b'\x00' * (32 - len(line))
            hex_part = ' '.join(f'{b:02x}' for b in line)
            print(f"      +0x{row:04x}: {hex_part}")
        # Dump key fields with offsets
        print(f"    KDBG field dump:")
        fields = [
            (0x00, 'ListEntry.Flink', 'Q'),
            (0x08, 'ListEntry.Blink', 'Q'),
            (0x10, 'OwnerTag', 'I'),
            (0x14, 'Size', 'I'),
            (0x18, 'KernBase', 'Q'),
            (0x20, 'BreakpointTable', 'Q'),
            (0x28, 'BreakpointTableSize', 'Q'),
            (0x30, 'KdDebuggerPresent', 'I'),
            (0x38, 'KiBugcheckData', 'Q'),
            (0x48, 'PsLoadedModuleList', 'Q'),
            (0x50, 'PsActiveProcessHead', 'Q'),
            (0x58, 'PspCidTable', 'Q'),
            (0x60, 'ExpSystemResourcesList', 'Q'),
            (0x68, 'ExpPagedPoolDescriptor', 'Q'),
            (0x70, 'ExpNumberOfPagedPools', 'Q'),
            (0x78, 'KeTimeIncrement', 'Q'),
            (0x80, 'KeBugCheckCallbackListHead', 'Q'),
            (0x88, 'KiBugcheckData', 'Q'),
            (0x90, 'IopErrorLogListHead', 'Q'),
            (0x98, 'ObpRootDirectoryObject', 'Q'),
            (0x108, 'MmLastUnloadedDriver', 'Q'),
            (0x110, 'MmLastUnloadedDriverNameLen', 'Q'),
            (0x118, 'KiProcessorBlock', 'Q'),
            (0x120, 'MmPfnDatabase', 'Q'),
            (0x270, 'MmPhysicalMemoryBlock', 'Q'),
        ]
        for off, name, fmt in fields:
            if off + 8 <= len(full):
                if fmt == 'Q':
                    v = struct.unpack_from('<Q', full, off)[0]
                    print(f"      +0x{off:04x} {name:35s} 0x{v:016x}")
                elif fmt == 'I':
                    v = struct.unpack_from('<I', full, off)[0]
                    print(f"      +0x{off:04x} {name:35s} 0x{v:08x}")
        print()
        return True

    # Pass 1: look for the classic 'KDBG' OwnerTag (offset 0x10).
    offset = 0
    while offset < data_sz:
        chunk_sz = min(480, data_sz - offset)
        chunk = gdb.read_memory(data_pa + offset, chunk_sz)
        if not chunk:
            break

        for o in range(16, len(chunk) - 0xD0, 4):
            if struct.unpack_from('<I', chunk, o)[0] != KDBG_TAG:
                continue
            k = o - 16
            if k < 0 or k + 0xD0 > len(chunk):
                continue
            kdbg_va = base_va + data_va + offset + k
            candidate_pa = data_pa + offset + k
            if _try_candidate(kdbg_va, candidate_pa):
                return

        offset += len(chunk) - 0xD0

    print("    KDBG tag scan failed, trying KernBase scan ...")

    # Pass 2: scan for a structure whose KernBase (offset 0x18) equals
    # the detected kernel base.  This avoids dependence on the OwnerTag.
    offset = 0
    while offset < data_sz:
        chunk_sz = min(480, data_sz - offset)
        chunk = gdb.read_memory(data_pa + offset, chunk_sz)
        if not chunk:
            break

        for k in range(0, len(chunk) - 0xD0, 8):
            kern_base = struct.unpack_from('<Q', chunk, k + KDBG_KernBase)[0]
            if kern_base != base_va:
                continue
            kdbg_va = base_va + data_va + offset + k
            candidate_pa = data_pa + offset + k
            if _try_candidate(kdbg_va, candidate_pa):
                return

        offset += len(chunk) - 0xD0

    print("    KDBG scan: no valid KDBG block found in .data")



def _read_physmem_descriptor_from_kdbg(gdb: GdbClient, info: KernelInfo,
                                        kdbg_va: int) -> Optional[PhysicalMemoryDescriptor]:
    """Read the system's physical memory descriptor via KdDebuggerDataBlock.

    KDDEBUGGER_DATA64.MmPhysicalMemoryBlock (offset 0x270) points to the
    PPHYSICAL_MEMORY_DESCRIPTOR global (&MmPhysicalMemoryBlock).  That global
    holds a pointer to the actual PHYSICAL_MEMORY_DESCRIPTOR, so we must
    dereference twice.  The x64 descriptor layout is:
      +0x00 NumberOfRuns  (Uint4B)    +0x08 NumberOfPages (Uint8B)
      +0x10 Run[i].BasePage (Uint8B)  +0x18 Run[i].PageCount (Uint8B)
    """
    if not kdbg_va:
        return None

    def _read_phys(va: int, length: int) -> Optional[bytes]:
        """Read kernel VA in phys mode via page-table walk.
        Must be called while already in phys mode."""
        pa = _va_to_pa(gdb, info.dtb, va)
        if not pa:
            return None
        data = gdb.read_memory(pa, length)
        if data and len(data) >= length:
            return data
        return None

    gdb.phys_mode()
    try:
        kdbg = _read_phys(kdbg_va, 0x278)
        if not kdbg:
            print("    KDBG descriptor: failed to read KDBG")
            return None
        # KDBG+0x270 = &MmPhysicalMemoryBlock (pointer variable address),
        # not the descriptor itself — dereference once more.
        pm_block_var_va = struct.unpack_from('<Q', kdbg, 0x270)[0]
        if not pm_block_var_va:
            print("    KDBG descriptor: MmPhysicalMemoryBlock is NULL")
            return None
        ptr_data = _read_phys(pm_block_var_va, 8)
        if not ptr_data:
            print(f"    KDBG descriptor: failed to dereference MmPhysicalMemoryBlock at 0x{pm_block_var_va:x}")
            return None
        pm_block_va = struct.unpack_from('<Q', ptr_data, 0)[0]
        if not pm_block_va:
            print("    KDBG descriptor: MmPhysicalMemoryBlock pointer is NULL")
            return None

        # Read descriptor header: NumberOfRuns(Uint4B) + pad + NumberOfPages(Uint8B)
        hdr = _read_phys(pm_block_va, 0x10)
        if not hdr:
            print(f"    KDBG descriptor: failed to read descriptor header at 0x{pm_block_va:x}")
            return None
        num_runs = struct.unpack_from('<I', hdr, 0)[0]
        num_pages = struct.unpack_from('<Q', hdr, 8)[0]
        if num_runs == 0 or num_runs > 256:
            print(f"    KDBG descriptor: bad num_runs={num_runs}")
            return None

        desc_size = 0x10 + num_runs * 16
        data = _read_phys(pm_block_va, desc_size)
        if not data:
            print(f"    KDBG descriptor: failed to read descriptor body ({desc_size} bytes)")
            return None

        runs = []
        for i in range(num_runs):
            off = 0x10 + i * 16
            base_page = struct.unpack_from('<Q', data, off)[0]
            page_count = struct.unpack_from('<Q', data, off + 8)[0]
            if page_count:
                runs.append(PhysicalMemoryRun(BasePage=base_page, PageCount=page_count))

        if not runs:
            print("    KDBG descriptor: no non-empty runs")
            return None

        print(f"    KDBG descriptor: {num_runs} run(s), {num_pages} pages")
        for i, r in enumerate(runs[:8]):
            print(f"      run {i}: base=0x{r.BasePage * PAGE_SIZE:x} pages={r.PageCount}")
        if len(runs) > 8:
            print(f"      ... and {len(runs) - 8} more")

        return PhysicalMemoryDescriptor(
            NumberOfRuns=len(runs),
            NumberOfPages=num_pages,
            Runs=runs,
        )
    except Exception as e:
        print(f"    KDBG descriptor: exception {e}")
        return None
    finally:
        gdb.virt_mode()


def discover_physical_memory(
    gdb: GdbClient, info: KernelInfo,
    user_ranges: Optional[List[Tuple[int, int]]] = None
) -> PhysicalMemoryDescriptor:
    if user_ranges:
        runs = [PhysicalMemoryRun(BasePage=s // PAGE_SIZE,
                                  PageCount=sz // PAGE_SIZE)
                for s, sz in user_ranges]
        return PhysicalMemoryDescriptor(
            NumberOfRuns=len(runs),
            NumberOfPages=sum(r.PageCount for r in runs),
            Runs=runs,
        )

    # Prefer the real descriptor from KDBG if available.
    pm = _read_physmem_descriptor_from_kdbg(gdb, info, info.kd_debugger_data_block)
    if pm:
        # The DUMP_HEADER64 PhysicalMemoryBlock can hold ~42 runs (700 bytes).
        # If KDBG reports more, warn and fall back to the simple 2-run model.
        if pm.NumberOfRuns > 42:
            print(f"    KDBG descriptor has {pm.NumberOfRuns} runs (too many for header)")
        else:
            print(f"    Physical memory descriptor from KDBG: {pm.NumberOfRuns} run(s)")
            # CR3 page may live in the 640KB-1MB BIOS hole.  WinDbg
            # needs it for page-table walks — inject unconditionally.
            pm = _ensure_dtb_in_runs(pm, info.dtb)
            return pm

    # Detect RAM from page table
    ram = _detect_ram_from_pagetable(gdb, info)
    if ram == 0:
        ram = 256 * 1024 * 1024

    mb1 = 0x100000
    return PhysicalMemoryDescriptor(
        NumberOfRuns=2,
        NumberOfPages=ram // PAGE_SIZE,
        Runs=[
            PhysicalMemoryRun(BasePage=0,              PageCount=mb1 // PAGE_SIZE),
            PhysicalMemoryRun(BasePage=mb1//PAGE_SIZE,  PageCount=(ram-mb1)//PAGE_SIZE),
        ],
    )

def _ensure_dtb_in_runs(pm: PhysicalMemoryDescriptor, dtb: int) -> PhysicalMemoryDescriptor:
    """Ensure the DTB (CR3) page is included in the descriptor runs.

    On x64 the CR3 page often lives in the 640KB-1MB BIOS hole that the
    system physical memory descriptor omits.  WinDbg MUST be able to walk
    page tables from this page, so we inject (or merge) it unconditionally.
    """
    if not dtb:
        return pm
    cr3_pfn = dtb >> 12

    # Already covered?
    for r in pm.Runs:
        if r.BasePage <= cr3_pfn < r.BasePage + r.PageCount:
            return pm

    # Build a sorted run list and grow whichever run touches the CR3 page,
    # or insert a single-page run.
    runs = sorted(pm.Runs, key=lambda r: r.BasePage)
    merged = []
    for r in runs:
        if r.BasePage <= cr3_pfn < r.BasePage + r.PageCount:
            merged.append(r)
        elif cr3_pfn < r.BasePage:
            if merged and merged[-1].BasePage + merged[-1].PageCount >= cr3_pfn:
                pass  # already covered by previous extension
            else:
                # Insert the CR3 page (or bridge to next run if adjacent).
                if merged and merged[-1].BasePage + merged[-1].PageCount + 1 >= cr3_pfn:
                    merged[-1].PageCount = max(merged[-1].PageCount,
                                               cr3_pfn - merged[-1].BasePage + 1)
                elif cr3_pfn + 1 == r.BasePage:
                    r = PhysicalMemoryRun(BasePage=cr3_pfn,
                                          PageCount=r.PageCount + 1)
                else:
                    merged.append(PhysicalMemoryRun(BasePage=cr3_pfn, PageCount=1))
            merged.append(r)
        else:
            merged.append(r)

    if not merged:
        merged = [PhysicalMemoryRun(BasePage=cr3_pfn, PageCount=1)]

    injected = len(merged) != len(pm.Runs) or any(
        a.BasePage != b.BasePage or a.PageCount != b.PageCount
        for a, b in zip(merged, pm.Runs))

    if injected:
        print(f"    Injected DTB page PFN=0x{cr3_pfn:x} (PA 0x{cr3_pfn*PAGE_SIZE:x}) into descriptor")

    return PhysicalMemoryDescriptor(
        NumberOfRuns=len(merged),
        NumberOfPages=sum(r.PageCount for r in merged),
        Runs=merged,
    )


def _detect_ram_from_pagetable(gdb: GdbClient, info: KernelInfo) -> int:
    """Estimate total RAM from highest physical address in page tables."""
    cr3 = info.dtb
    if not cr3:
        return 0

    max_pa = 0
    gdb.phys_mode()
    try:
        pml4_entries = _batch_read_pte(gdb, cr3 & ~0xFFF, 512)
        for pml4_idx in range(512):
            pml4e = pml4_entries[pml4_idx]
            if not (pml4e & 1):
                continue
            pdpt_pa = pml4e & 0x000FFFFFFFFFF000
            pdpt_entries = _batch_read_pte(gdb, pdpt_pa, 512)
            for pdpt_idx in range(512):
                pdpte = pdpt_entries[pdpt_idx]
                if not (pdpte & 1):
                    continue
                if pdpte & 0x80:  # 1GB page
                    max_pa = max(max_pa, (pdpte & 0x000FFFFFFFFFF000) + (1 << 30))
                    continue
                pd_pa = pdpte & 0x000FFFFFFFFFF000
                pd_entries = _batch_read_pte(gdb, pd_pa, 512)
                for pd_idx in range(512):
                    pde = pd_entries[pd_idx]
                    if not (pde & 1):
                        continue
                    if pde & 0x80:  # 2MB page
                        max_pa = max(max_pa, (pde & 0x000FFFFFFFFFF000) + (2 << 20))
                        continue
                    # 4KB page table — descend only if the large-page ceiling
                    # looks suspiciously low.  Walking every PT is slow.
                    if max_pa < (512 << 20):  # < 512 MB from large pages so far
                        # Cap PT walks to avoid stalling on huge sparse mappings.
                        pt_pa = pde & 0x000FFFFFFFFFF000
                        pt_entries = _batch_read_pte(gdb, pt_pa, 512)
                        for pt_idx in range(512):
                            pte = pt_entries[pt_idx]
                            if pte & 1:
                                max_pa = max(max_pa, (pte & 0x000FFFFFFFFFF000) + PAGE_SIZE)
    finally:
        gdb.virt_mode()
    if max_pa > 0:
        max_pa = (max_pa + 0x3FFFFF) & ~0x3FFFFF
    return max_pa


# ═══════════════════════════════════════════════════════════════
#  Context record
# ═══════════════════════════════════════════════════════════════

def read_context(gdb: GdbClient, arch: str) -> bytes:
    regs = gdb.read_all_regs_dict()
    return _ctx_x64(regs) if arch != 'x86' else _ctx_x86(regs)


def _ctx_x86(regs: Dict[str, int]) -> bytes:
    buf = bytearray(1232)
    struct.pack_into('<I', buf, 0, 0x10007)
    for nm, off in [('edi',0x9C),('esi',0xA0),('ebx',0xA4),('edx',0xA8),
                    ('ecx',0xAC),('eax',0xB0),('ebp',0xB4),('eip',0xB8),
                    ('eflags',0xC0),('esp',0xC4),('cs',0xBC),('ss',0xC8),
                    ('ds',0x98),('es',0x94),('fs',0x90),('gs',0x8C)]:
        if nm in regs:
            struct.pack_into('<I', buf, off, regs[nm] & 0xFFFFFFFF)
    return bytes(buf)


def _ctx_x64(regs: Dict[str, int]) -> bytes:
    buf = bytearray(3000)
    # WinDbg accepts the dump-header context in the legacy dump layout
    # (flags at +0) while newer consumers inspect the native AMD64
    # CONTEXT layout (flags at +0x30). Populate both.
    context_flags = 0x0010001F  # CONTEXT_AMD64 | CONTROL | INTEGER | SEGMENTS | FP | DEBUG
    struct.pack_into('<I', buf, 0x00, context_flags)
    struct.pack_into('<I', buf, 0x30, context_flags)
    struct.pack_into('<I', buf, 0x34, regs.get('mxcsr', 0x1F80) & 0xFFFFFFFF)

    for nm, off in [('rax',0x78),('rcx',0x80),('rdx',0x88),('rbx',0x90),
                    ('rsp',0x98),('rbp',0xA0),('rsi',0xA8),('rdi',0xB0),
                    ('r8',0xB8),('r9',0xC0),('r10',0xC8),('r11',0xD0),
                    ('r12',0xD8),('r13',0xE0),('r14',0xE8),('r15',0xF0),
                    ('rip',0xF8),('eflags',0x44)]:
        if nm in regs:
            struct.pack_into('<Q', buf, off, regs[nm])

    for nm, off in [('cs',0x38),('ds',0x3A),('es',0x3C),
                    ('fs',0x3E),('gs',0x40),('ss',0x42)]:
        if nm in regs:
            struct.pack_into('<H', buf, off, regs[nm] & 0xFFFF)
    return bytes(buf)
