# FakePDB

Tool for PDB generation from IDA Pro database

Supports:
* IDA >= 7.4

## TODO

* Linux support
* GHIDRA support
* Function arguments support

## How to get

* Download latest release from release page: https://github.com/Mixaill/FakePDB/releases
* Or compile it from sources:
   * run `<repository_root>/build.ps1`
   * grab `fakepdb.zip` from `<repository_root>/~build/deploy`

## How to install

* IDA
  * copy content of `fakepdb.zip/ida` to `<IDA_directory>/plugins`

## How to use

There are several features in this plugin:

### PDB file generation
  * Open target executable in IDA
  * `Edit` -> `FakePDB` -> `Generate .PDB file` (or `Ctrl`+`Shift`+`4`)
  * get PDB file from the IDA database directory

  The PDB can optionally include symbols for function labels: use `Generate .PDB file (with function labels)` (or `Ctrl`+`Shift`+`5`).

### LIB file generation
  * Open target executable in IDA
  * `Edit` -> `FakePDB` -> `Generate .LIB file`
  * get LIB file from the IDA database directory

### IDA database export to .json
  * Open target executable in IDA >= 7.0
  * `Edit` -> `FakePDB` -> `Dump info to .json` (or `Ctrl`+`Shift`+`1`)
  * it will generate `filename.json` near the `.idb` file

### Binary signature search
  * Open target executable in IDA >= 7.0
  * Set cursor on start of the target function
  * `Edit` -> `FakePDB` -> `Find signature` (or `Ctrl`+`Shift`+`2`)
  * signature will be displayed in IDA console

### Function names import from `.json` file
  * Open target executable in IDA >= 7.0
  * `Edit` -> `FakePDB` -> `Import offset from .json` (or `Ctrl`+`Shift`+`3`)

required file format:
```json
{
   "function_name_1": "0001:123456",
   "function_name_2": "0001:254646",
   "function_name_X": "XXXX:YYYYYY",
   "function_name_Y": "0x0124567AF",
}
```

where:
 * `XXXX`: number of the PE section
 * `YYYY`: offset from the begining of the section in decimal numbers
 * 0x0124567AF: IDA effective address


## Thanks

Inspired by:
  * pe_debug http://pefrm-units.osdn.jp/pe_debug.html

Based on:
  * LLVM project https://llvm.org/
  * LLD project https://lld.llvm.org/
  
Also take look at:
  * bao https://github.com/not-wlan/bao
