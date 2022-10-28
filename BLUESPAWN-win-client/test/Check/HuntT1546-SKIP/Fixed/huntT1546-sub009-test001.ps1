$passed = $true
if (Test-Path "HKLM:\System\CurrentControlSet\Control\Session Manager"){
    try {
        $value = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "AppCertDLLs" -ErrorAction SilentlyContinue
        if ($value.appcertdlls -eq "C:\Temp\evil.dll"){
            Write-Output "Hunt-T1546-Sub009-Test001: Registry value not removed."
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
return $passed