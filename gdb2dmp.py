#!/usr/bin/env gdb -x
"""
gdb2dmp.py — GDB Python script: convert live Windows VM to crash dump.

Run entirely inside gdb.exe — no external Python process needed.

Usage:
  gdb.exe -batch -ex "source gdb2dmp.py" -ex "gdb2dmp 127.0.0.1:8864 bsod.dmp"

All memory reads use gdb.inferior().read_memory() — GDB's C internals
handle the RSP protocol, no pipeline desync, no hex encoding overhead.
"""

import gdb
import struct
import os
import re
import time

# ═══════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════

PAGE_SIZE = 4096
POOLCODE_QWORD = 0x45444F434C4F4F50  # "POOLCODE"
KDBG_TAG = 0x4742444B                 # "KDBG"

# DUMP_HEADER64 offsets
DH64_SIGNATURE = 0x0000
DH64_VALID_DUMP = 0x0004
DH64_MAJOR_VERSION = 0x0008
DH64_MINOR_VERSION = 0x000c
DH64_DIRECTORY_TABLE_BASE = 0x0010
DH64_PFN_DATA_BASE = 0x0018
DH64_PS_LOADED_MODULE_LIST = 0x0020
DH64_PS_ACTIVE_PROCESS_HEAD = 0x0028
DH64_MACHINE_IMAGE_TYPE = 0x0030
DH64_NUMBER_PROCESSORS = 0x0034
DH64_BUGCHECK_CODE = 0x0038
DH64_BUGCHECK_PARAMETER1 = 0x0040
DH64_BUGCHECK_PARAMETER2 = 0x0048
DH64_BUGCHECK_PARAMETER3 = 0x0050
DH64_BUGCHECK_PARAMETER4 = 0x0058
DH64_VERSION_USER = 0x0060
DH64_KD_DEBUGGER_DATA_BLOCK = 0x0080
DH64_PHYSICAL_MEMORY_BLOCK = 0x0088
DH64_CONTEXT_RECORD = 0x0348
DH64_EXCEPTION = 0x0f00
DH64_DUMP_TYPE = 0x0f98
DH64_REQUIRED_DUMP_SPACE = 0x0fa0
DH64_SYSTEM_TIME = 0x0fa8
DH64_COMMENT = 0x0fb0
DH64_SYSTEM_UP_TIME = 0x1030
DH64_MINI_DUMP_FIELDS = 0x1038
DH64_SECONDARY_DATA_STATE = 0x103C
DH64_PRODUCT_TYPE = 0x1040
DH64_SUITE_MASK = 0x1044
DH64_WRITER_STATUS = 0x104c
DH64_KD_SECONDARY_VERSION = 0x104d

DUMP_SIGNATURE64 = 0x45474150   # 'PAGE'
DUMP_VALID_DUMP64 = 0x34365544  # 'DU64'
IMAGE_FILE_MACHINE_AMD64 = 0x8664
DUMP_HEADER64_SIZE = 8192
DUMP_TYPE_FULL = 1
MAX_DUMP_HEADER64_RUNS = (DH64_CONTEXT_RECORD - (DH64_PHYSICAL_MEMORY_BLOCK + 0x10)) // 16

def _gdb_cli_filename(path):
    """Return a GDB memory-dump filename.

    GDB's dump/append memory commands on Windows pass double quotes through
    to CreateFile instead of treating them as CLI quoting, so quoted paths fail
    with ERROR_INVALID_PARAMETER. Use forward slashes and leave the path bare.
    """
    return os.path.abspath(path).replace('\\', '/')

KUSER_SHARED_DATA = 0xFFFFF78000000000

# KDBG field offsets (Win7+ x64)
KDBG_KernBase = 0x18
KDBG_PsLoadedModuleList = 0x48
KDBG_PsActiveProcessHead = 0x50
KDBG_MmPfnDatabase = 0xC0  # offset 0x120 in newer, 0xC0 in Win7
KDBG_KiBugcheckData = 0x88
KDBG_MmPhysicalMemoryBlock = 0x270


# ═══════════════════════════════════════════════════════════════
#  Low-level memory access (via GDB inferior)
# ═══════════════════════════════════════════════════════════════

def _phys_mode():
    gdb.execute("monitor phys", to_string=True)

def _virt_mode():
    gdb.execute("monitor virt", to_string=True)

def _read_mem(addr, length):
    """Read memory at addr (current mode). Returns bytes."""
    try:
        mem = gdb.selected_inferior().read_memory(addr, length)
        return bytes(mem)
    except Exception:
        return b''

def _read_phys(pa, length):
    """Read physical memory."""
    _phys_mode()
    return _read_mem(pa, length)

def _read_virt(va, length):
    """Read virtual memory."""
    _virt_mode()
    return _read_mem(va, length)

def _read_qword_phys(pa):
    d = _read_phys(pa, 8)
    return struct.unpack_from('<Q', d, 0)[0] if len(d) >= 8 else 0



# ═══════════════════════════════════════════════════════════════
#  Page table walk
# ═══════════════════════════════════════════════════════════════

def _va_to_pa(cr3, va):
    """Walk x64 page tables in phys mode. Returns PA of va."""
    pml4_idx = (va >> 39) & 0x1FF
    pdpt_idx = (va >> 30) & 0x1FF
    pd_idx = (va >> 21) & 0x1FF
    pt_idx = (va >> 12) & 0x1FF
    page_off = va & 0xFFF

    pml4e = _read_qword_phys((cr3 & ~0xFFF) + pml4_idx * 8)
    if not (pml4e & 1):
        return 0
    pdpte = _read_qword_phys((pml4e & 0x000FFFFFFFFFF000) + pdpt_idx * 8)
    if not (pdpte & 1):
        return 0
    if pdpte & (1 << 7):  # 1GB large page
        return (pdpte & 0x000FFFFFFFFFF000) + (va & 0x3FFFFFFF)
    pde = _read_qword_phys((pdpte & 0x000FFFFFFFFFF000) + pd_idx * 8)
    if not (pde & 1):
        return 0
    if pde & (1 << 7):  # 2MB large page
        return (pde & 0x000FFFFFFFFFF000) + (va & 0x1FFFFF)
    pte = _read_qword_phys((pde & 0x000FFFFFFFFFF000) + pt_idx * 8)
    if not (pte & 1):
        return 0
    return (pte & 0x000FFFFFFFFFF000) + page_off

def _read_kernel_va(cr3, va, length):
    """Read kernel VA by walking page tables and reading physical pages."""
    out = bytearray()
    while length > 0:
        pa = _va_to_pa(cr3, va)
        if not pa:
            break
        n = min(length, PAGE_SIZE - (va & (PAGE_SIZE - 1)))
        data = _read_phys(pa, n)
        if len(data) != n:
            break
        out.extend(data)
        va += n
        length -= n
    return bytes(out)


# ═══════════════════════════════════════════════════════════════
#  Register access
# ═══════════════════════════════════════════════════════════════

def _get_cr3():
    try:
        out = gdb.execute("monitor r cr3", to_string=True)
        m = re.search(r'cr3\s*=\s*(0x[0-9a-fA-F]+)', out)
        if m:
            return int(m.group(1), 16)
    except:
        pass
    try:
        out = gdb.execute("print/x $cr3", to_string=True)
        m = re.search(r'=\s*(0x[0-9a-fA-F]+)', out)
        if m:
            return int(m.group(1), 16)
    except:
        pass
    return 0

def _read_all_regs():
    """Read all GP registers as dict."""
    out = gdb.execute("info registers", to_string=True)
    result = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0].lower()
            try:
                result[name] = int(parts[1], 0)
            except ValueError:
                pass
    return result


# ═══════════════════════════════════════════════════════════════
#  Kernel detection
# ═══════════════════════════════════════════════════════════════

def _is_kernel_pe_header(pa):
    """Check if physical address contains valid MZ+PE+POOLCODE."""
    hdr = _read_phys(pa, 0x800)
    if len(hdr) < 0x200 or hdr[:2] != b'MZ':
        return False
    e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
    if e_lfanew + 24 > len(hdr):
        return False
    if struct.unpack_from('<I', hdr, e_lfanew)[0] != 0x00004550:  # 'PE\0\0'
        return False
    # Check for POOLCODE signature in first 0x800 bytes
    for i in range(0, len(hdr) - 8, 8):
        if struct.unpack_from('<Q', hdr, i)[0] == POOLCODE_QWORD:
            return True
    return False

def _detect_kernel_base(cr3, rip):
    """Detect kernel base VA by scanning 2MB-aligned addresses near RIP."""
    print(f"[*] Detecting kernel base ...")
    print(f"    CR3 = 0x{cr3:x}, RIP = 0x{rip:x}")

    # First try: probe candidate VAs near RIP
    step = 0x200000  # 2MB
    radius = 0x80000000  # 2GB
    start_va = (rip & ~0x1FFFFF) - radius

    for va in range(start_va, start_va + 2 * radius, step):
        if va < 0xFFFF800000000000:
            continue
        pa = _va_to_pa(cr3, va)
        if pa and _is_kernel_pe_header(pa):
            print(f"    kernel base = 0x{va:x} (PA 0x{pa:x})")
            return va
        # Progress
        if (va - start_va) % (step * 256) == 0:
            pct = (va - start_va) * 100 // (2 * radius)
            print(f"    scanning... {pct}% (va=0x{va:x})")

    print("    kernel base not found via VA scan")
    return 0


# ═══════════════════════════════════════════════════════════════
#  KDBG scan
# ═══════════════════════════════════════════════════════════════

def _scan_kdbg(cr3, kernel_base_va):
    """Scan kernel .data section for KDBG block. Returns dict of kernel info."""
    print("[*] Scanning for KDBG ...")
    # Read PE header for section table.
    hdr = _read_kernel_va(cr3, kernel_base_va, 0x1000)
    if len(hdr) < 0x100 or hdr[:2] != b'MZ':
        print("    ERROR: invalid kernel PE header")
        return {}

    e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
    opt_hdr_size = struct.unpack_from('<H', hdr, e_lfanew + 20)[0]
    num_sections = struct.unpack_from('<H', hdr, e_lfanew + 6)[0]
    sec_start = e_lfanew + 24 + opt_hdr_size

    # Read section table
    sec_data = _read_kernel_va(cr3, kernel_base_va + sec_start, num_sections * 40)
    if len(sec_data) < num_sections * 40:
        print("    ERROR: short section table read")
        return {}

    data_va = data_sz = 0
    for i in range(num_sections):
        s = sec_data[i*40:(i+1)*40]
        name = s[:8].rstrip(b'\x00').decode('ascii', errors='replace')
        if name == '.data':
            data_va = struct.unpack_from('<I', s, 12)[0]
            data_sz = struct.unpack_from('<I', s, 8)[0] or struct.unpack_from('<I', s, 16)[0]
            break

    if not data_va or not data_sz:
        print("    ERROR: .data section not found")
        return {}

    print(f"    .data: VA=0x{data_va:x} size=0x{data_sz:x}")
    # Scan for KDBG tag. Use page-table-backed VA reads instead of assuming
    # the mapped image is physically contiguous.
    KDBG_STRUCT_SIZE = 0x280
    chunk_len = 0x10000
    step = chunk_len - KDBG_STRUCT_SIZE
    offset = 0
    while offset < data_sz:
        chunk_sz = min(chunk_len, data_sz - offset)
        chunk = _read_kernel_va(cr3, kernel_base_va + data_va + offset, chunk_sz)
        if not chunk or len(chunk) < 0x20:
            break

        limit = len(chunk) - 4

        for o in range(16, limit, 4):
            if struct.unpack_from('<I', chunk, o)[0] != KDBG_TAG:
                continue
            k = o - 16
            if k < 0 or k + KDBG_STRUCT_SIZE > len(chunk):
                continue
            kdbg_va = kernel_base_va + data_va + offset + k
            # Read full KDBG from VA; the structure may cross a physical page.
            full = _read_kernel_va(cr3, kdbg_va, KDBG_STRUCT_SIZE)
            if len(full) < KDBG_STRUCT_SIZE:
                continue
            kern_base = struct.unpack_from('<Q', full, KDBG_KernBase)[0]
            if kern_base != kernel_base_va:
                continue
            plm = struct.unpack_from('<Q', full, KDBG_PsLoadedModuleList)[0]
            paph = struct.unpack_from('<Q', full, KDBG_PsActiveProcessHead)[0]
            pfn = struct.unpack_from('<Q', full, KDBG_MmPfnDatabase)[0]
            pmblock = struct.unpack_from('<Q', full, KDBG_MmPhysicalMemoryBlock)[0]

            if not (plm and paph and pfn and pmblock):
                continue

            print(f"    KDBG found at VA 0x{kdbg_va:x}")
            print(f"      KernBase            = 0x{kern_base:x}")
            print(f"      PsLoadedModuleList  = 0x{plm:x}")
            print(f"      PsActiveProcessHead = 0x{paph:x}")
            print(f"      MmPfnDatabase       = 0x{pfn:x}")
            print(f"      MmPhysicalMemoryBlock = 0x{pmblock:x}")
            # Force-populate page tables by reading KDBG in virt mode
            _virt_mode()
            _read_mem(kdbg_va, 0x60)
            for cva in [plm, paph, pfn, pmblock]:
                if cva:
                    _read_mem(cva, 8)
            _phys_mode()

            return {
                'kd_debugger_data_block': kdbg_va,
                'ps_loaded_module_list': plm,
                'ps_active_process_head': paph,
                'pfn_database': pfn,
                'mm_physical_memory_block': pmblock,
            }

        if chunk_sz < chunk_len:
            break
        offset += step

    print("    ERROR: KDBG not found")
    return {}

def _find_kernel_export_va(cr3, kernel_base_va, export_name):
    """Find a kernel PE export and return its VA."""
    try:
        hdr = _read_kernel_va(cr3, kernel_base_va, 0x1000)
        if len(hdr) < 0x100 or hdr[:2] != b'MZ':
            return 0
        e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
        opt_off = e_lfanew + 24
        exp_rva = struct.unpack_from('<I', hdr, opt_off + 0x70)[0]
        if not exp_rva:
            return 0

        expdir = _read_kernel_va(cr3, kernel_base_va + exp_rva, 40)
        if len(expdir) < 40:
            return 0
        num_names = struct.unpack_from('<I', expdir, 24)[0]
        addr_funcs = struct.unpack_from('<I', expdir, 28)[0]
        addr_names = struct.unpack_from('<I', expdir, 32)[0]
        addr_ords = struct.unpack_from('<I', expdir, 36)[0]
        if not num_names or not addr_names or num_names > 0x10000:
            return 0

        names_arr = _read_kernel_va(cr3, kernel_base_va + addr_names, num_names * 4)
        ord_arr = _read_kernel_va(cr3, kernel_base_va + addr_ords, num_names * 2)
        if len(names_arr) < num_names * 4 or len(ord_arr) < num_names * 2:
            return 0

        name_rvas = [struct.unpack_from('<I', names_arr, i * 4)[0] for i in range(num_names)]
        if not name_rvas:
            return 0
        min_rva = min(name_rvas)
        max_rva = max(name_rvas)
        region = _read_kernel_va(cr3, kernel_base_va + min_rva, min(max_rva - min_rva + 32, 0x10000))
        target = export_name.encode('ascii')
        for i, name_rva in enumerate(name_rvas):
            off = name_rva - min_rva
            if 0 <= off < len(region):
                end = region.find(b'\x00', off)
                if end < 0:
                    end = len(region)
                if region[off:end] == target:
                    ordinal = struct.unpack_from('<H', ord_arr, i * 2)[0]
                    funcs_arr = _read_kernel_va(cr3, kernel_base_va + addr_funcs, (ordinal + 1) * 4)
                    if len(funcs_arr) >= (ordinal + 1) * 4:
                        func_rva = struct.unpack_from('<I', funcs_arr, ordinal * 4)[0]
                        return kernel_base_va + func_rva
        return 0
    except Exception:
        return 0


def _read_nt_build_number(cr3, kernel_base_va):
    """Read exported NtBuildNumber from the kernel image."""
    va = _find_kernel_export_va(cr3, kernel_base_va, 'NtBuildNumber')
    if not va:
        return 0
    data = _read_kernel_va(cr3, va, 4)
    return (struct.unpack_from('<I', data, 0)[0] & 0xFFFF) if len(data) >= 4 else 0


def _read_ke_number_processors(cr3, kernel_base_va):
    """Read exported KeNumberProcessors (UCHAR)."""
    va = _find_kernel_export_va(cr3, kernel_base_va, 'KeNumberProcessors')
    if not va:
        return 1
    data = _read_kernel_va(cr3, va, 1)
    count = data[0] if data else 1
    return count if 1 <= count <= 0x40 else 1


# ═══════════════════════════════════════════════════════════════
#  Physical memory descriptor
# ═══════════════════════════════════════════════════════════════

def _read_physmem_descriptor(kdbg_va):
    """Read PHYSICAL_MEMORY_DESCRIPTOR from KDBG.

    All addresses here are kernel VAs — use virt mode throughout.
    """
    if not kdbg_va:
        return None

    _virt_mode()
    # KDBG+0x270 = &MmPhysicalMemoryBlock (pointer variable address)
    kdbg = _read_mem(kdbg_va, 0x278)
    if not kdbg or len(kdbg) < 0x278:
        print("    KDBG descriptor: failed to read KDBG")
        return None

    pm_block_var_va = struct.unpack_from('<Q', kdbg, 0x270)[0]
    if not pm_block_var_va:
        print("    KDBG descriptor: MmPhysicalMemoryBlock is NULL")
        return None

    # Dereference: &MmPhysicalMemoryBlock -> MmPhysicalMemoryBlock
    ptr_data = _read_mem(pm_block_var_va, 8)
    if len(ptr_data) < 8:
        print(f"    KDBG descriptor: failed to deref at 0x{pm_block_var_va:x}")
        return None
    pm_block_va = struct.unpack_from('<Q', ptr_data, 0)[0]
    if not pm_block_va:
        print("    KDBG descriptor: MmPhysicalMemoryBlock pointer is NULL")
        return None

    # Read descriptor header: NumberOfRuns(Uint4B) + pad + NumberOfPages(Uint8B)
    hdr = _read_mem(pm_block_va, 0x10)
    if len(hdr) < 0x10:
        print(f"    KDBG descriptor: failed to read header at 0x{pm_block_va:x}")
        return None
    num_runs = struct.unpack_from('<I', hdr, 0)[0]
    num_pages = struct.unpack_from('<Q', hdr, 8)[0]
    if num_runs == 0 or num_runs > 256:
        print(f"    KDBG descriptor: bad num_runs={num_runs}")
        return None

    # Read full descriptor
    desc_size = 0x10 + num_runs * 16
    data = _read_mem(pm_block_va, desc_size)
    if len(data) < desc_size:
        print(f"    KDBG descriptor: failed to read body ({desc_size} bytes)")
        return None

    runs = []
    for i in range(num_runs):
        off = 0x10 + i * 16
        bp = struct.unpack_from('<Q', data, off)[0]
        pc = struct.unpack_from('<Q', data, off + 8)[0]
        if pc:
            runs.append((bp, pc))

    if not runs:
        print("    KDBG descriptor: no non-empty runs")
        return None

    print(f"    KDBG descriptor: {num_runs} run(s), {num_pages} pages")
    for i, (bp, pc) in enumerate(runs[:8]):
        print(f"      run {i}: base=0x{bp * PAGE_SIZE:x} pages={pc}")
    if len(runs) > 8:
        print(f"      ... and {len(runs) - 8} more")

    return (runs, num_pages)

def _normalize_runs(runs):
    """Drop empty runs and merge overlapping or adjacent PFN ranges."""
    merged = []
    for bp, pc in sorted((int(bp), int(pc)) for bp, pc in runs if pc > 0):
        end = bp + pc
        if merged and merged[-1][0] + merged[-1][1] >= bp:
            base, count = merged[-1]
            merged[-1] = (base, max(base + count, end) - base)
        else:
            merged.append((bp, pc))
    return merged


# ═══════════════════════════════════════════════════════════════
#  Context record
# ═══════════════════════════════════════════════════════════════

def _build_context_x64():
    """Build a WinDbg-compatible x64 context record from GDB registers."""
    regs = _read_all_regs()
    buf = bytearray(3000)

    # WinDbg accepts the dump-header context in the legacy dump layout
    # (flags at +0) while newer consumers may inspect the native AMD64
    # CONTEXT layout (flags at +0x30). Populate both; +0 is P1Home in the
    # native layout and is harmless if treated that way.
    context_flags = 0x0010001F  # CONTEXT_AMD64 | CONTROL | INTEGER | SEGMENTS | FP | DEBUG
    struct.pack_into('<I', buf, 0x00, context_flags)
    struct.pack_into('<I', buf, 0x30, context_flags)
    struct.pack_into('<I', buf, 0x34, regs.get('mxcsr', 0x1F80) & 0xFFFFFFFF)

    reg_map = {
        'rax': 0x78, 'rcx': 0x80, 'rdx': 0x88, 'rbx': 0x90,
        'rsp': 0x98, 'rbp': 0xA0, 'rsi': 0xA8, 'rdi': 0xB0,
        'r8': 0xB8, 'r9': 0xC0, 'r10': 0xC8, 'r11': 0xD0,
        'r12': 0xD8, 'r13': 0xE0, 'r14': 0xE8, 'r15': 0xF0,
        'rip': 0xF8,
    }
    for name, off in reg_map.items():
        if name in regs:
            struct.pack_into('<Q', buf, off, regs[name] & 0xFFFFFFFFFFFFFFFF)

    if 'eflags' in regs:
        struct.pack_into('<I', buf, 0x44, regs['eflags'] & 0xFFFFFFFF)

    seg_map = {
        'cs': 0x38, 'ds': 0x3A, 'es': 0x3C,
        'fs': 0x3E, 'gs': 0x40, 'ss': 0x42,
    }
    for name, off in seg_map.items():
        if name in regs:
            struct.pack_into('<H', buf, off, regs[name] & 0xFFFF)

    return bytes(buf)


# ═══════════════════════════════════════════════════════════════
#  Dump header builder
# ═══════════════════════════════════════════════════════════════

def _build_header(info, runs, ctx_bytes):
    """Build 8KB DUMP_HEADER64."""
    num_pages = sum(pc for _, pc in runs)
    if len(runs) > MAX_DUMP_HEADER64_RUNS:
        raise ValueError(f"too many physical memory runs for DUMP_HEADER64: {len(runs)}")
    buf = bytearray(DUMP_HEADER64_SIZE)
    # Fill with PAGE signature
    for i in range(0, len(buf), 4):
        struct.pack_into('<I', buf, i, DUMP_SIGNATURE64)

    struct.pack_into('<I', buf, DH64_SIGNATURE, DUMP_SIGNATURE64)
    struct.pack_into('<I', buf, DH64_VALID_DUMP, DUMP_VALID_DUMP64)
    struct.pack_into('<I', buf, DH64_MAJOR_VERSION, info.get('major_version', 10))
    struct.pack_into('<I', buf, DH64_MINOR_VERSION, info.get('minor_version', 0))
    struct.pack_into('<Q', buf, DH64_DIRECTORY_TABLE_BASE, info['dtb'])
    struct.pack_into('<Q', buf, DH64_PFN_DATA_BASE, info.get('pfn_database', 0))
    struct.pack_into('<Q', buf, DH64_PS_LOADED_MODULE_LIST, info.get('ps_loaded_module_list', 0))
    struct.pack_into('<Q', buf, DH64_PS_ACTIVE_PROCESS_HEAD, info.get('ps_active_process_head', 0))
    struct.pack_into('<I', buf, DH64_MACHINE_IMAGE_TYPE, IMAGE_FILE_MACHINE_AMD64)
    struct.pack_into('<I', buf, DH64_NUMBER_PROCESSORS, info.get('number_processors', 1))
    struct.pack_into('<I', buf, DH64_BUGCHECK_CODE, 0xE2)
    struct.pack_into('<Q', buf, DH64_BUGCHECK_PARAMETER1, 0)
    struct.pack_into('<Q', buf, DH64_BUGCHECK_PARAMETER2, 0)
    struct.pack_into('<Q', buf, DH64_BUGCHECK_PARAMETER3, 0)
    struct.pack_into('<Q', buf, DH64_BUGCHECK_PARAMETER4, 0)
    struct.pack_into('<Q', buf, DH64_KD_DEBUGGER_DATA_BLOCK, info.get('kd_debugger_data_block', 0))
    # Version user string
    buf[DH64_VERSION_USER:DH64_KD_DEBUGGER_DATA_BLOCK] = b'\x00' * (DH64_KD_DEBUGGER_DATA_BLOCK - DH64_VERSION_USER)
    ver = b"gdb2dmp"
    buf[DH64_VERSION_USER:DH64_VERSION_USER + len(ver)] = ver
    # Physical memory descriptor
    runs_to_write = len(runs)
    struct.pack_into('<I', buf, DH64_PHYSICAL_MEMORY_BLOCK, runs_to_write)
    struct.pack_into('<Q', buf, DH64_PHYSICAL_MEMORY_BLOCK + 8, num_pages)
    p = DH64_PHYSICAL_MEMORY_BLOCK + 0x10
    for i in range(runs_to_write):
        bp, pc = runs[i]
        struct.pack_into('<Q', buf, p, bp); p += 8
        struct.pack_into('<Q', buf, p, pc); p += 8

    # Context record
    if ctx_bytes:
        ctx = ctx_bytes[:3000]
        buf[DH64_CONTEXT_RECORD:DH64_CONTEXT_RECORD + len(ctx)] = ctx

    # Exception record (full EXCEPTION_RECORD64 = 0x98 bytes)
    p = DH64_EXCEPTION
    struct.pack_into('<I', buf, p, 0x80000003); p += 4  # ExceptionCode
    struct.pack_into('<I', buf, p, 1); p += 4           # ExceptionFlags
    struct.pack_into('<Q', buf, p, 0); p += 8           # ExceptionRecord
    struct.pack_into('<Q', buf, p, 0); p += 8           # ExceptionAddress
    struct.pack_into('<I', buf, p, 0); p += 4           # NumberParameters
    p += 4                                              # padding
    for _ in range(15):
        struct.pack_into('<Q', buf, p, 0); p += 8       # ExceptionInformation
    struct.pack_into('<I', buf, DH64_DUMP_TYPE, DUMP_TYPE_FULL)
    struct.pack_into('<Q', buf, DH64_REQUIRED_DUMP_SPACE, DUMP_HEADER64_SIZE + num_pages * PAGE_SIZE)

    st = info.get('system_time', 0)
    ut = info.get('system_up_time', 0)
    if not st:
        st = int(time.time() * 10000000) + 116444736000000000
    struct.pack_into('<Q', buf, DH64_SYSTEM_TIME, st)
    struct.pack_into('<Q', buf, DH64_SYSTEM_UP_TIME, ut)
    buf[DH64_COMMENT:DH64_SYSTEM_UP_TIME] = b'\x00' * (DH64_SYSTEM_UP_TIME - DH64_COMMENT)
    struct.pack_into('<I', buf, DH64_PRODUCT_TYPE, info.get('product_type', 0))
    struct.pack_into('<I', buf, DH64_SUITE_MASK, info.get('suite_mask', 0))
    struct.pack_into('<I', buf, DH64_MINI_DUMP_FIELDS, 0)
    struct.pack_into('<I', buf, DH64_SECONDARY_DATA_STATE, 0)
    struct.pack_into('<B', buf, DH64_WRITER_STATUS, 0)
    struct.pack_into('<B', buf, DH64_KD_SECONDARY_VERSION, 0)
    return bytes(buf)


# ═══════════════════════════════════════════════════════════════
#  Main dump command
# ═══════════════════════════════════════════════════════════════

class Gdb2DmpCommand(gdb.Command):
    """gdb2dmp <host:port> <output.dmp>

    Convert a live Windows VM (via GDB stub) to a crash dump file.
    All operations run inside GDB — memory reads use GDB's C internals.
    """

    def __init__(self):
        super().__init__("gdb2dmp", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            print("Usage: gdb2dmp <host:port> <output.dmp>")
            return

        target = args[0]
        output = args[1]

        host, _, port_str = target.partition(':')
        if not host or not port_str:
            print("Usage: gdb2dmp <host:port> <output.dmp>")
            return
        try:
            port = int(port_str)
        except ValueError:
            print(f"ERROR: invalid port: {port_str}")
            return

        # ── 1. Connect ──
        print(f"[*] Connecting to {host}:{port} ...")
        gdb.execute(f"target remote {host}:{port}", to_string=True)
        gdb.execute("set pagination off", to_string=True)
        gdb.execute("set endian little", to_string=True)

        # ── 2. Read CR3 and RIP ──
        cr3 = _get_cr3()
        if not cr3:
            print("ERROR: cannot read CR3")
            return
        print(f"    CR3 = 0x{cr3:x}")

        regs = _read_all_regs()
        rip = regs.get('rip', regs.get('eip', 0))
        print(f"    RIP = 0x{rip:x}")

        # ── 3. Detect kernel base ──
        kernel_base = _detect_kernel_base(cr3, rip)
        if not kernel_base:
            print("ERROR: kernel base not detected")
            return

        # ── 4. KDBG scan ──
        info = _scan_kdbg(cr3, kernel_base)
        info['dtb'] = cr3
        info['kernel_base'] = kernel_base

        if not info.get('kd_debugger_data_block'):
            print("WARNING: KdDebuggerDataBlock not found; dump may not load in WinDbg")

        # ── 5. Read physical memory descriptor ──
        print("[*] Discovering physical memory layout ...")
        result = _read_physmem_descriptor(info.get('kd_debugger_data_block', 0))
        if result:
            runs, _ = result
        else:
            # Fallback: detect RAM from page tables
            ram = 256 * 1024 * 1024
            mb1 = 0x100000
            runs = [(0, mb1 // PAGE_SIZE), (mb1 // PAGE_SIZE, (ram - mb1) // PAGE_SIZE)]

        runs = _normalize_runs(runs)

        # Ensure DTB page is in runs.
        cr3_pfn = cr3 >> 12
        if not any(bp <= cr3_pfn < bp + pc for bp, pc in runs):
            runs = _normalize_runs(runs + [(cr3_pfn, 1)])

        if len(runs) > MAX_DUMP_HEADER64_RUNS:
            print(f"ERROR: too many physical memory runs for DUMP_HEADER64: {len(runs)} > {MAX_DUMP_HEADER64_RUNS}")
            return

        num_pages = sum(pc for _, pc in runs)
        print(f"    {len(runs)} run(s), {num_pages} pages ({num_pages * PAGE_SIZE // (1024*1024)} MB)")

        # ── 6. Read CPU context ──
        print("[*] Reading CPU context ...")
        _virt_mode()
        ctx = _build_context_x64()

        # ── 7. Read KUSER_SHARED_DATA ──
        kuser = {}
        try:
            kdata = _read_virt(KUSER_SHARED_DATA, 0x280)
            if len(kdata) >= 0x18 + 8:
                kuser['system_time'] = struct.unpack_from('<Q', kdata, 0x14)[0]
            if len(kdata) >= 0x10:
                kuser['system_up_time'] = struct.unpack_from('<Q', kdata, 0x08)[0]
            if len(kdata) >= 0x268:
                kuser['product_type'] = struct.unpack_from('<I', kdata, 0x260)[0]
        except:
            pass

        build_number = _read_nt_build_number(cr3, kernel_base)
        if build_number:
            print(f"    NtBuildNumber = {build_number}")

        processor_count = _read_ke_number_processors(cr3, kernel_base)
        print(f"    KeNumberProcessors = {processor_count}")

        info['system_time'] = kuser.get('system_time', 0)
        info['system_up_time'] = kuser.get('system_up_time', 0)
        info['product_type'] = kuser.get('product_type', 0)
        info['suite_mask'] = kuser.get('suite_mask', 0)
        info['number_processors'] = processor_count
        # dbgeng uses the dump header version pair to decide whether the
        # target uses 64-bit kernel debugger-data APIs.  For x64 full dumps
        # this must be (DUMP_MAJOR_VERSION, NtBuildNumber), not (10, 0).
        info['major_version'] = 0x0F
        info['minor_version'] = build_number or 0

        # ── 8. Build and write dump header ──
        print(f"[*] Writing dump header to {output} ...")
        header = _build_header(info, runs, ctx)
        with open(output, 'wb') as f:
            f.write(header)

        dtb_hdr = struct.unpack_from('<Q', header, 0x10)[0]
        kdbg_hdr = struct.unpack_from('<Q', header, 0x80)[0]
        print(f"    Header DTB  = 0x{dtb_hdr:x}")
        print(f"    Header KdDebuggerDataBlock = 0x{kdbg_hdr:x}")

        # ── 9. Append physical memory directly through GDB ──
        total_mb = num_pages * PAGE_SIZE // (1024 * 1024)
        print(f"[*] Dumping {total_mb} MB physical memory ...")

        _phys_mode()
        t0 = time.time()
        total_bytes = num_pages * PAGE_SIZE
        written = 0
        output_for_gdb = _gdb_cli_filename(output)

        for run_idx, (base_page, page_count) in enumerate(runs):
            pa_start = base_page * PAGE_SIZE
            pa_size = page_count * PAGE_SIZE
            run_mb = pa_size // (1024 * 1024)
            pa_end = pa_start + pa_size
            print(f"  Run {run_idx}: 0x{pa_start:x} ({run_mb} MB)")

            gdb.execute(f"append binary memory {output_for_gdb} 0x{pa_start:x} 0x{pa_end:x}",
                        to_string=True)
            written += pa_size
            pct = written * 100 // total_bytes
            mb_done = written // (1024 * 1024)
            elapsed = time.time() - t0
            speed = (written / 1024 / 1024) / elapsed if elapsed > 0 else 0
            eta = (total_bytes - written) / (speed * 1024 * 1024) if speed > 0 else 0
            print(f"    {pct}% ({mb_done}/{total_mb} MB) {speed:.1f} MB/s ETA {eta:.0f}s")
        elapsed = time.time() - t0
        speed = (written / 1024 / 1024) / elapsed if elapsed > 0 else 0
        print(f"[*] Done: {output} ({written // (1024*1024)} MB in {elapsed:.1f}s, {speed:.1f} MB/s)")
        print(f"[*] Analyze with:  windbg -z {output}")
        _virt_mode()
        gdb.execute("disconnect", to_string=True)
        print("[*] Disconnected from target.")
        return
# Register the command
Gdb2DmpCommand()
print("gdb2dmp command registered. Usage: gdb2dmp <host:port> <output.dmp>")
