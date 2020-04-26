# FakePDB

Tool for PDB generation from IDA Pro database

Inspired by:
  * pe_debug http://pefrm-units.osdn.jp/pe_debug.html

Based on:
  * LLVM project https://llvm.org/
  * LLD project https://lld.llvm.org/

## How to compile

* compile LLVM with PDB support (LLVM >= 10 required)

```shell
git clone https://github.com/llvm/llvm-project ./llvm_project

cmake "./llvm_project/llvm/" -B"./llvm_project_build" -DCMAKE_INSTALL_PREFIX="./_prefix" -DLLVM_ENABLE_PDB=ON

cmake --build "./llvm_project_build" --config Release --target INSTALL
```

* compile pdbgen

```shell
git clone https://github.com/Mixaill/FakePDB ./fakepdb

cmake "./fakepdb/src_pdbgen/" -B"./pdbgen_build" -DCMAKE_INSTALL_PREFIX="./install" -DCMAKE_PREFIX_PATH="./_prefix"

cmake --build "./pdbgen_build" --config Release --target INSTALL
```

## How to use

1. Export information from IDA database
    * Open target executable in IDA >= 7.0
    * `File` -> `Script file ...`
    * select `<pdbgen_repository>/src_ida/dumpinfo.py`
    * it will generate `filename.json` near the `.idb` file

2. Generate PDB
   * drag `filename.exe` to `pdbgen.exe`
   * it will generate `filename.pdb` near the `filename.exe`

## TODO

* GHIDRA support
* PE32+ support
* Function arguments support
* Create IDA plugin
