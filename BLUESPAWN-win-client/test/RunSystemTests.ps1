del *.json
.\RunAttacks.ps1
#Run BLUESPAWN args[0] is path to BLUESPAWN
$yes = "y`n"*1000
$job = Start-Job -Init ([ScriptBlock]::Create("Set-Location '$pwd'")) -ScriptBlock {
    &$args[0] --hunt --log=json -a Intensive --hunts "T1037,T1068,T1136,T1543,T1547,T1553,T1562" -r "remove-value,delete-file"
} -ArgumentList $args[0] -InputObject $yes
#&$args[0] --hunt --log=xml -a Intensive --hunts T1546 -r "remove-value,delete-file"
Wait-Job $job -Timeout 120
Receive-Job $job
Stop-Job $job
$fixedPassed = .\CheckFixed.ps1
$checkPassed = .\CheckCaught.ps1
.\CleanUp.ps1
Write-Output "Attacks Remediated:"
Write-Output $fixedPassed
$fixedPassed = ($fixedPassed -split "`n") | Select-Object -Last 1
Write-Output "Attacks Caught:"
Write-Output $checkPassed
$checkPassed = ($checkPassed -split "`n") | Select-Object -Last 1
return ($fixedPassed -eq "True") -band ($checkPassed -eq "True")