# FakePDB

Tool for PDB generation from IDA Pro database

Supports:
* IDA >= 7.4 

## Download

* [Windows AMD64](https://nightly.link/Mixaill/FakePDB/workflows/CI/master/binaries.zip)

## How to install

* IDA
  * copy content of `binaries.zip/ida` to `<IDA_directory>/plugins`

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

## TODO

* Linux support
* GHIDRA support
* Function arguments support
* IDA 9.0: structures export

## Useful links

* Disable PDB validation in WinDbg [http://ntcoder.com/bab/2012/03/06/how-to-force-symbol-loading-in-windbg/](https://web.archive.org/web/20200130221144/http://ntcoder.com/bab/2012/03/06/how-to-force-symbol-loading-in-windbg/)
* Disable PDB validation in MSVS https://stackoverflow.com/questions/38147487/forcing-to-load-unmatched-symbols-in-visual-studio-2015-debugger

## Mentions

* [2019, Google Project Zero: The story of Adobe Reader symbols](https://googleprojectzero.blogspot.com/2019/10/the-story-of-adobe-reader-symbols.html)
* [2021, Gerhart X.: Hyper-V debugging for beginners. 2nd edition.](https://hvinternals.blogspot.com/2021/01/hyper-v-debugging-for-beginners-2nd.html)
* [2022, Google Cloud: Fuzzing Image Parsing in Windows, Part Four: More HEIF](https://cloud.google.com/blog/topics/threat-intelligence/fuzzing-image-parsing-windows-part-four/)

## Thanks

Inspired by:
  * pe_debug http://pefrm-units.osdn.jp/pe_debug.html

Based on:
  * LLVM project https://llvm.org/
  * LLD project https://lld.llvm.org/
  
Also take look at:
  * bao https://github.com/not-wlan/bao
