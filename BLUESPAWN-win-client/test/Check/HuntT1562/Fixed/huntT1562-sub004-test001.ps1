$passed = $true
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\AuthorizedApplications\List"){
    try {
        $properties = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\AuthorizedApplications\List" -ErrorAction SilentlyContinue
        if ($properties){
            $value = Get-Member -InputObject $properties -Name "C:\Windows\Temp\T1562004001.exe" 
            if ($value){
                Write-Output "Hunt-T1562-Sub004-Test001: Registry value not removed"
                $passed = $false;
            }
        }
    } 
    catch{
        $passed = $true
    }
}
if (Test-Path "C:\Windows\Temp\T1562004001.exe"){
    Write-Output "Hunt-T1562-Sub004-Test001: File not removed"
    $passed = $false;
}
return $passed