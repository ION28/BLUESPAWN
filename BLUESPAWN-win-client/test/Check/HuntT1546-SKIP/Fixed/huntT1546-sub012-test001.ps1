$passed = $true
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe"){
    try {
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" -Name "ReportingMode" -ErrorAction SilentlyContinue
        if ($value.ReportingMode -eq 1){
            Write-Output "HuntT1546-Sub012-Test001: Reporting Mode registry key not remediated."
            $passed = $false;
        }
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" -Name "MonitorProcess" -ErrorAction SilentlyContinue
        if ($value.MonitorProcess -eq "C:\temp\evil.exe"){
            Write-Output "HuntT1546-Sub012-Test001: Monitor Process registry key not remediated."
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
return $passed