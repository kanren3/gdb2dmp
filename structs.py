"""
Windows crash dump file structure definitions.

Based on Windows Server 2003 / XP kernel source (ntos/io/iomgr/dumpctl.h, ntiodump.h).
"""

from enum import IntEnum
from dataclasses import dataclass, field
from typing import List


# ── Constants ──────────────────────────────────────────────────

# DUMP_HEADER signature constants
DUMP_SIGNATURE32 = 0x45474150   # 'PAGE'
DUMP_SIGNATURE64 = 0x45474150   # 'PAGE'
DUMP_VALID_DUMP32 = 0x504d5544  # 'DUMP'
DUMP_VALID_DUMP64 = 0x34365544  # 'DU64'

PAGE_SIZE = 4096

# Windows 7 x64 DUMP_HEADER64 layout (from private ntoskrnl symbols)
DUMP_HEADER64_SIZE = 8192
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
DH64_SECONDARY_DATA_STATE = 0x103c
DH64_PRODUCT_TYPE = 0x1040
DH64_SUITE_MASK = 0x1044
DH64_WRITER_STATUS = 0x104c
DH64_KD_SECONDARY_VERSION = 0x104d

# DUMP_TYPE enum
class DumpType(IntEnum):
    DUMP_TYPE_INVALID = 0
    DUMP_TYPE_FULL = 1
    DUMP_TYPE_SUMMARY = 2
    DUMP_TYPE_HEADER = 3
    DUMP_TYPE_TRIAGE = 4
    DUMP_TYPE_BITMAP_FULL = 5
    DUMP_TYPE_BITMAP_KERNEL = 6
    DUMP_TYPE_AUTOMATIC = 7

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664


# ── PHYSICAL_MEMORY_DESCRIPTOR ─────────────────────────────────

@dataclass
class PhysicalMemoryRun:
    """Single contiguous physical memory run."""
    BasePage: int   # starting PFN
    PageCount: int  # number of pages


@dataclass
class PhysicalMemoryDescriptor:
    """Describes all physical memory in the system."""
    NumberOfRuns: int
    NumberOfPages: int
    Runs: List[PhysicalMemoryRun] = field(default_factory=list)
