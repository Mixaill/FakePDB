#
# Config
#

$build_llvm = $true

#
# Set environment 
#

Push-Location $PSScriptRoot
$root = (Get-Location).Path -replace "\\","/"

#https://stackoverflow.com/a/64744522
Push-Location "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools"
cmd /c "VsDevCmd.bat -arch=amd64 -host_arch=amd64&set " |
ForEach-Object {
  if ($_ -match "=") {
    $v = $_.split("="); set-item -force -path "ENV:\$($v[0])"  -value "$($v[1])"
  }
}
Pop-Location

#
# Build LLVM
#

if($true -eq $build_llvm){
    git clone --depth=1 https://github.com/llvm/llvm-project "./~build/llvm_git"

    cmake "./~build/llvm_git/llvm" `
        -B"./~build/llvm_build" `
        -GNinja `
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

    cmake --build "./~build/llvm_build"
    cmake --install "./~build/llvm_build"
}

#
# Build PDBGen
#

cmake "./src_cpp/" `
    -B"./~build/fakepdb_build" `
    -GNinja `
    -DCMAKE_BUILD_TYPE="Release" `
    -DCMAKE_INSTALL_PREFIX="./~build/fakepdb_install" `
    -DCMAKE_PREFIX_PATH="$root/~build/llvm_install"

cmake --build "./~build/fakepdb_build"
cmake --install "./~build/fakepdb_build"

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
    Sign-Folder -Folder "./~build/fakepdb_install/bin/"
    Write-Output ""
}

#
# Copy files
#

New-Item -Path "./~build/deploy/ida" -ItemType Directory -ErrorAction SilentlyContinue
Copy-Item -Path "./src_plugins/ida/*" -Destination "./~build/deploy/ida/" -Recurse

New-Item -Path "./~build/deploy/ida/fakepdb/win32/" -ItemType Directory -ErrorAction SilentlyContinue
Copy-Item -Path "./~build/fakepdb_install/bin/*.exe" -Destination "./~build/deploy/ida/fakepdb/win32/" -Recurse

#
# Pack files
#
Compress-Archive -Path "./~build/deploy/*" -DestinationPath "./~build/deploy/fakepdb.zip"

Pop-Location