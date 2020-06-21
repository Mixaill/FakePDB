Push-Location $PSScriptRoot
$root = (Get-Location).Path -replace "\\","/"

#
# Build LLVM
#

git clone --depth=1 https://github.com/llvm/llvm-project "./~build/llvm_git" -q

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

#
# Build PDBGen
#

cmake "./src_pdbgen/" -B"./~build/pdbgen_build" -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INSTALL_PREFIX="./~build/pdbgen_install" -DCMAKE_PREFIX_PATH="$root/~build/llvm_install"
cmake --build "./~build/pdbgen_build" --config Release --target INSTALL


#
# Sign
#

function Sign-IsAvailable(){
    return $null -ne $(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert)
}
function Sign-File($FilePath, $TimestampServer = "http://time.certum.pl/")
{
    $cert=Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
    Set-AuthenticodeSignature -FilePath $FilePath -Certificate $cert -TimestampServer $TimestampServer
}

function Sign-Folder($Folder, $Filters = @("*.exe", "*.dll"), $TimestampServer = "http://time.certum.pl/")
{
    foreach($filter in $Filters){
        $files = Get-ChildItem -Path $Folder -Filter $filter -Recurse -ErrorAction SilentlyContinue -Force

        foreach ($file in $files) {
            Sign-File -FilePath $file.FullName -TimestampServer $TimestampServer
        }
    }
}

if(Sign-IsAvailable){
    Write-Output "Signing files"
    Sign-Folder -Folder "./~build/pdbgen_install/bin/"
    Write-Output ""
}

#
# Copy files
#

New-Item -Path "./~build/deploy" -ItemType Directory -ErrorAction SilentlyContinue
Copy-Item -Path "./src_ida/*" -Destination "./~build/deploy/" -Recurse
New-Item -Path "./~build/deploy/fakepdb/win32/" -ItemType Directory -ErrorAction SilentlyContinue
Copy-Item -Path "./~build/pdbgen_install/bin/*.exe" -Destination "./~build/deploy/fakepdb/win32/" -Recurse

#
# Pack files
#
Compress-Archive -Path "./~build/deploy/*" -DestinationPath "./~build/deploy/fakepdb.zip"

Pop-Location