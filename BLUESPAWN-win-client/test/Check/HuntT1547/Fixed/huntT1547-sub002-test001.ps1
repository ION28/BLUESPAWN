$passed = $true
if (Test-Path "HKLM:\System\CurrentControlSet\Control\LSA"){
    try {
        $value = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA" -Name "Authentication Packages" -ErrorAction SilentlyContinue
        if ($value.'Authentication Packages' -like "*T1547002001*"){
            Write-Output "Hunt-T1547-Sub002-Test001: Registry value not removed"
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
if (Test-Path "C:\Windows\System32\T1547002001.dll"){
    Write-Output "Hunt-T1547-Sub002-Test001: File not removed"
    $passed = $false;
}
return $passed