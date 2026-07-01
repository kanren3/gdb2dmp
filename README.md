# gdb2dmp

`gdb2dmp.py` is a Python script loaded by GDB. It converts a Windows x64 virtual machine with a GDB remote stub into a full kernel dump that can be loaded by WinDbg.

## How it works

- Connect to the GDB remote stub.
- Search for the kernel base and KdDebuggerDataBlock to build the DumpHeader.
- Read the physical memory layout from MmPhysicalMemoryBlock, then read and write DumpMemory.

## Usage

```bat
gdb -batch -ex "source gdb2dmp.py" -ex "gdb2dmp 127.0.0.1:8864 snapshot.dmp"
```

## Requirements

- A Windows x64 virtual machine with a GDB remote stub.
- The GDB stub must support following features:
  - `monitor r cr3`
  - `monitor phys`
  - `monitor virt`
