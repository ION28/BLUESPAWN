$passed = $true
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSdb\{12345678-9ABC-DEF0-1234-56789ABCDEF0}"){
    try {
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSdb\{12345678-9ABC-DEF0-1234-56789ABCDEF0}" -Name "DatabaseDescription" -ErrorAction SilentlyContinue
        if ($value.DatabaseDescription -eq "Firefox Update"){
            Write-Output "Hunt-T1546-Sub011-Test001: Registry value DatabaseDescription not removed."
            $passed = $false;
        }
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSdb\{12345678-9ABC-DEF0-1234-56789ABCDEF0}" -Name "DatabasePath" -ErrorAction SilentlyContinue
        if ($value.DatabasePath -eq "C:\Program Files\evil.sdb"){
            Write-Output "Hunt-T1546-Sub011-Test001: Registry value DatabasePath not removed."
            $passed = $false;
        }
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSdb\{12345678-9ABC-DEF0-1234-56789ABCDEF0}" -Name "DatabaseRuntimePlatform" -ErrorAction SilentlyContinue
        if ($value.DatabaseRuntimePlatform -eq "4"){
            Write-Output "Hunt-T1546-Sub011-Test001: Registry value DatabaseRuntimePlatform not removed."
            $passed = $false;
        }        
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSdb\{12345678-9ABC-DEF0-1234-56789ABCDEF0}" -Name "DatabaseType" -ErrorAction SilentlyContinue
        if ($value.DatabaseType -eq "65536"){
            Write-Output "Hunt-T1546-Sub011-Test001: Registry value DatabaseType not removed."
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"){
    try {
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" -Name "Firefox.exe" -ErrorAction SilentlyContinue
        if ($value.'Firefox.exe' -eq "{12345678-9ABC-DEF0-1234-56789ABCDEF0}"){
            Write-Output "Hunt-T1546-Sub011-Test001: Registry value Custom\Firefox.exe not removed."
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
return $passed