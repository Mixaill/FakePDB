# FakePDB

Tool for PDB generation from IDA Pro database

Inspired by:
  * pe_debug http://pefrm-units.osdn.jp/pe_debug.html

Based on:
  * LLVM project https://llvm.org/
  * LLD project https://lld.llvm.org/

## How to compile

* run `./build.ps1`

* grab `fakepdb.zip` from `<repo>/~build/deploy`

## How to install

* copy content of `fakepdb.zip` to `<IDA_directory>/plugins`

## How to use

### 1. Export information from IDA database
    * Open target executable in IDA >= 7.0
    * `Edit` -> `FakePDB` -> `Dump info to .json` (or `Ctrl`+`Shift`+`1`)
    * it will generate `filename.json` near the `.idb` file

### 2. Find binary signature of function
  * Open target executable in IDA >= 7.0
  * Set cursor on start of the target function
  * `Edit` -> `FakePDB` -> `Find signature` (or `Ctrl`+`Shift`+`2`)
  * signature will be displayed in IDA console

### 3. Import function names from `.json` file
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

### 4. Generate PDB file
  * Open target executable in IDA >= 7.0
  * `Edit` -> `FakePDB` -> `Generate .PDB file` (or `Ctrl`+`Shift`+`4`)
  * get PDB file from the IDA database directory

## TODO

* GHIDRA support
* Function arguments support
