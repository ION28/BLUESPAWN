$passed = $true
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"){
    try {
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name "Debugger" -ErrorAction SilentlyContinue
        if ($value.Debugger -eq "C:\temp\evil.exe"){
            Write-Output "HuntT1546-Sub008-Test001: Registry key not removed."
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
return $passed