$passed = $true
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports"){
    Write-Output "HERE"
    try {
        $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports"  -Name "Evil" -ErrorAction SilentlyContinue
        if ($value.'Evil' -eq "C:\Windows\Temp\T1068002.dll"){
            Write-Output "Hunt-T1068-Test002: Registry value not removed"
            $passed = $false
        }
    } 
    catch{
        Write-Output "HI"
    }
}
if (Test-Path "C:\Windows\Temp\T1068002.dll"){
    Write-Output "Hunt-T1068-Test002: File not deleted"
    $passed = $false
}
return $passed