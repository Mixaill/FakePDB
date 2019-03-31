# FakePDB

Tool for PDB generation from IDA Pro database

Inspired by:
  * pe_debug http://pefrm-units.osdn.jp/pe_debug.html

Based on:
  * LLVM project https://llvm.org/
  * LLD project https://lld.llvm.org/

## How to use

1. Compile `pdbgen` (requires LLVM)

2. Generate IDA dump
    * Open target executable in IDA >= 7.0
    * `File` -> `Script file ...`
    * select `src_ida/dumpinfo.py`
    * it will generate `filename.json` near the `.idb` file

3. Generate PDB
   * drag `filename.exe` to `pdbgen.exe`
   * it will generate `filename.pdb` near the `filename.exe`

## TODO

* GHIDRA support
* PE32+ support
* Function arguments support
