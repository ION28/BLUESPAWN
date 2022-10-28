$passed = $true
if (Test-Path "HKCU:\SOFTWARE\Classes\CLSID\{12345678-9ABC-DEF0-1234-56789ABCDEF0}"){
    try {
        $value = Get-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{12345678-9ABC-DEF0-1234-56789ABCDEF0}" -Name "InprocHandler32" -ErrorAction SilentlyContinue
        if ($value.InprocHandler32 -eq "C:\Windows\System32\1546015001.dll"){
            Write-Output "Hunt-T1546-Sub015-Test001: Registry key not remediated."
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
if (Test-Path "C:\Windows\System32\1546015001.dll"){
    Write-Output "Hunt-T1545-Sub015-Test001: File not remediated"
    $passed = $false
}
return $passed