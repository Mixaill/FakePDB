Push-Location $PSScriptRoot
$root = (Get-Location).Path -replace "\\","/"

#clone LLVM
git clone https://github.com/llvm/llvm-project "./~build/llvm_git" -q

#build LLVM
cmake "./~build/llvm_git/llvm" -B"./~build/llvm_build" `
    -DCMAKE_BUILD_TYPE="Release" `
    -DCMAKE_INSTALL_PREFIX="./~build/llvm_install" `
    -DLLVM_BUILD_LLVM_C_DYLIB=OFF `
    -DLLVM_BUILD_RUNTIME=OFF `
    -DLLVM_BUILD_RUNTIMES=OFF `
    -DLLVM_BUILD_TOOLS=OFF `
    -DLLVM_BUILD_UTILS=OFF `
    -DLLVM_ENABLE_BACKTRACES=OFF `
    -DLLVM_ENABLE_BINDINGS=OFF `
    -DLLVM_ENABLE_CRASH_OVERRIDES=OFF `
    -DLLVM_ENABLE_OCAMLDOC=OFF `
    -DLLVM_ENABLE_PDB=ON `
    -DLLVM_INCLUDE_BENCHMARKS=OFF `
    -DLLVM_INCLUDE_DOCS=OFF `
    -DLLVM_INCLUDE_EXAMPLES=OFF `
    -DLLVM_INCLUDE_GO_TESTS=OFF `
    -DLLVM_INCLUDE_RUNTIMES=OFF `
    -DLLVM_INCLUDE_TESTS=OFF `
    -DLLVM_INCLUDE_TOOLS=OFF `
    -DLLVM_INCLUDE_UTILS=OFF `
    -DLLVM_TARGETS_TO_BUILD=""

cmake --build "./~build/llvm_build" --config Release --target INSTALL

#build PDBgen
cmake "./src_pdbgen/" -B"./~build/pdbgen_build" -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INSTALL_PREFIX="./~build/pdbgen_install" -DCMAKE_PREFIX_PATH="$root/~build/llvm_install"
cmake --build "./~build/pdbgen_build" --config Release --target INSTALL

#copy files
New-Item -Path "./~build/deploy" -ItemType Directory -ErrorAction SilentlyContinue
New-Item -Path "./~build/deploy/fakepdb/bin/" -ItemType Directory -ErrorAction SilentlyContinue
Copy-Item -Path "./src_ida/*" -Destination "./~build/deploy/" -Recurse
Copy-Item -Path "./~build/pdbgen_install/bin/*.exe" -Destination "./~build/deploy/fakepdb/win32/" -Recurse

#pack files
Compress-Archive -Path "./~build/deploy/*" -DestinationPath "./~build/deploy/fakepdb.zip"

Pop-Location