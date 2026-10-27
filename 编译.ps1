$ErrorActionPreference = 'Stop'
$frameworkPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$compilerPath = Join-Path $frameworkPath 'csc.exe'
if (-not (Test-Path -LiteralPath $compilerPath)) { throw '未找到 Windows 自带的 64 位 C# 编译器。' }
Push-Location -LiteralPath $PSScriptRoot
try {
    & $compilerPath /nologo /target:winexe /platform:x64 /optimize+ '/out:星脉资源管家.exe' '/resource:界面.xaml,UI' "/reference:$frameworkPath\WPF\PresentationFramework.dll" "/reference:$frameworkPath\WPF\PresentationCore.dll" "/reference:$frameworkPath\WPF\WindowsBase.dll" "/reference:$frameworkPath\System.Xaml.dll" "/reference:$frameworkPath\System.Drawing.dll" '程序.cs'
    if ($LASTEXITCODE -ne 0) { throw '编译失败。请先关闭正在运行的资源管家，再检查编译信息。' }
    Write-Host '编译完成：星脉资源管家.exe'
} finally {
    Pop-Location
}
