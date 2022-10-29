$passed = $true
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\GloballyOpenPorts\List"){
    try {
        $properties = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\GloballyOpenPorts\List" -ErrorAction SilentlyContinue
        if ($properties){
            $value = Get-Member -InputObject $properties -Name "1562"
            if ($value){
                Write-Output "Hunt-T1562-Sub004-Test002: Registry value not removed"
                $passed = $false;
            }
        }
    } 
    catch{
        $passed = $true
    }
}
return $passed