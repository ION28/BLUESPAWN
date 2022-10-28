$passed = $true
if (Test-Path "HKLM:\Software\Microsoft\NetSh"){
    try {
        $value = Get-ItemProperty -Path "HKLM:\Software\Microsoft\NetSh" -Name "evil" -ErrorAction SilentlyContinue
        if ($value.evil -eq "evil.dll"){
            Write-Output "Hunt-T1546-Sub007-Test001: Registry value not removed."
            $passed = $false;
        }
    } 
    catch{
        Write-Output "HI"
    }
}
if (Test-Path "C:\Windows\System32\evil.dll"){
    Write-Output "Hunt-T1546-Sub007-Test001: Malicious file not deleted."
    $passed = $false
}
return $passed