#!/usr/bin/env pwsh

#
# Config
#

param (
    [switch] $build_llvm = $false,
    [switch] $install_llvm = $false,
    [switch] $generate_msvc = $false
)

#
# Set root dir
#
Push-Location $PSScriptRoot
$root = (Get-Location).Path -replace "\\","/"


#
# Helpers
#

function Get-OS()
{
    if($PSVersionTable.PSEdition -ne "Core")
    {
        return "windows"
    }

    if($PSVersionTable.OS.StartsWith("Microsoft"))
    {
        return "windows"
    }

    if(Get-Command "uname" -errorAction SilentlyContinue)
    {
        return "$(uname -s)".ToLower()
    }

    return "unknown"
}

# the return value needs to match Python's platform.machine().lower()
function Get-Architecture()
{
    $os = Get-OS

    if($os -eq "windows")
    {
        switch(${env:PROCESSOR_ARCHITECTURE})
        {
            AMD64
            {
                return "amd64"
            }
            x86
            {
                return "i686"
            }
            ARM64
            {
                return "arm64"
            }
        }
    }
    elseif(Get-Command "uname" -errorAction SilentlyContinue)
    {
        return "$(uname -m)".ToLower()
    }

    return "Unknown"
}

function Set-BuildEnvironment(){
    if("windows" -eq $(Get-OS)){
        #https://stackoverflow.com/a/64744522
        $location = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools"
        if (!(Test-Path -Path $location)) {
            $location = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools"
        }
        if (!(Test-Path -Path $location)) {
            Write-Error "MSVC was not found"
            exit 1
        }
        Push-Location $location
        cmd /c "VsDevCmd.bat -arch=amd64 -host_arch=amd64&set " |
        ForEach-Object {
        if ($_ -match "=") {
            $v = $_.split("="); set-item -force -path "ENV:\$($v[0])"  -value "$($v[1])"
        }
        }
        Pop-Location
    }
}


function Sign-IsAvailable(){
    if ("windows" -ne $(Get-OS)){
        return $false
    }

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


#
# Build functions
#

function Build-LLVM(){
    if (Test-Path -Path "./~build/llvm_git"){
        Push-Location "./~build/llvm_git"
        git reset --hard
        git pull
        Pop-Location
    }
    else{
        git clone --depth=1 https://github.com/llvm/llvm-project "./~build/llvm_git"
    }

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

    cmake --build "./~build/llvm_build" --parallel
    cmake --install "./~build/llvm_build"
}

function Install-LLVM(){
    #$llvm_version = "$(llvm-cov --version)" -replace '[^\d]*(\d+(\.\d+){1,3})[^\d]*', '$1'
    $llvm_version = "21.1.5"
    $url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-$llvm_version/clang+llvm-$llvm_version-x86_64-pc-windows-msvc.tar.xz"
    Invoke-WebRequest -Uri $url -OutFile llvm.tar.xz
    tar -xzf llvm.tar.xz
    mkdir -p "$root/~build/llvm_install"
    Move-Item "clang+llvm-$llvm_version-x86_64-pc-windows-msvc/*" "$root/~build/llvm_install"
    Get-ChildItem "$root/~build/llvm_install"
    $env:PATH = "$(Get-Location)\~build\llvm_install\bin;" + $env:PATH
    #llvm-config --version

    # workaround
    mkdir -p "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\DIA SDK\lib\amd64"
    Copy-Item "$env:VSINSTALLDIR\DIA SDK\lib\amd64\diaguids.lib" "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\DIA SDK\lib\amd64\diaguids.lib"
}

function Build-FakePDB(){
    if ($generate_msvc -eq $true) {
        cmake "./src_cpp/" `
            -B"./~build/fakepdb_build" `
            -DCMAKE_BUILD_TYPE="Release" `
            -DCMAKE_INSTALL_PREFIX="./~build/fakepdb_install" `
            -DCMAKE_PREFIX_PATH="$root/~build/llvm_install"
    }

    cmake "./src_cpp/" `
        -B"./~build/fakepdb_build_ninja" `
        -GNinja `
        -DCMAKE_BUILD_TYPE="Release" `
        -DCMAKE_INSTALL_PREFIX="./~build/fakepdb_install" `
        -DCMAKE_PREFIX_PATH="$root/~build/llvm_install"

    cmake --build "./~build/fakepdb_build_ninja" --parallel
    cmake --install "./~build/fakepdb_build_ninja"
}


#
# Build pipeline
#

function Build(){
    Set-BuildEnvironment

    if($true -eq $build_llvm){
        Build-LLVM
    }
    elseif($true -eq $install_llvm){
        Install-LLVM
    }

    Build-FakePDB

    if(Sign-IsAvailable){
        Write-Output "Signing files"
        Sign-Folder -Folder "./~build/fakepdb_install/bin/"
        Write-Output ""
    }
    
    #
    # Copy files
    #
    
    Remove-Item -Path "./~build/deploy/ida" -Recurse -ErrorAction SilentlyContinue
    New-Item -Path "./~build/deploy/ida" -ItemType Directory -ErrorAction SilentlyContinue
    Copy-Item -Path "./src_plugins/ida/*" -Destination "./~build/deploy/ida/" -Recurse
    

    $foldername = "$(Get-OS)_$(Get-Architecture)"
    New-Item -Path "./~build/deploy/ida/fakepdb/$foldername/" -ItemType Directory -ErrorAction SilentlyContinue
    Copy-Item -Path "./~build/fakepdb_install/bin/*" -Destination "./~build/deploy/ida/fakepdb/$foldername/" -Recurse
    
    #
    # Pack files
    #
    Remove-Item -Path "./~build/fakepdb.zip" -ErrorAction SilentlyContinue
    Compress-Archive -Path "./~build/deploy/*" -DestinationPath "./~build/fakepdb.zip"
      
}

Build

Pop-Location
