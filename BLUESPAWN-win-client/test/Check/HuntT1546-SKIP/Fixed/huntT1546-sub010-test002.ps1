$passed = $true
if (Test-Path "HKLM:\Software\Wow6432Node\Windows NT\CurrentVersion\Windows"){
    try {
        $value = Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
        if ($value.appinit_dlls -eq "C:\Temp\evil.dll"){
            Write-Output "Hunt-T1546-Sub010-Test002: Registry value not removed."
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
return $passed