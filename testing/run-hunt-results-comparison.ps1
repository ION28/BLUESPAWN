$tests = Import-Csv .\AtomicTestsResults.csv
[xml]$results = Get-Content .\BLUESPAWNHuntResults.xml

$TotalTests = 0
$TestsPassed = 0

ForEach($Technique in ($tests | ForEach-Object { $_.Technique } | get-unique)) {
	$TotalTests += 1

	$TechniqueTests = $tests | Where-Object { $_.Technique -eq $Technique }
	$TechniqueTestCount = (($TechniqueTests | Measure).count)
	
	$TechniqueResults = $results.bluespawn.hunt | Where-Object { $_.name -like "$Technique*" }
	$TechniqueDetectionCount = (($TechniqueResults.detection | Measure).count)
	
	if($TechniqueDetectionCount -ge $TechniqueTestCount) {
		Write-Host "${TechniqueTestCount}/${TechniqueTestCount} Tests for Technique ${Technique}: PASSED"
		$TestsPassed += 1
	} else {
		Write-Host "${TechniqueDetectionCount}/${TechniqueTestCount} Tests for Technique ${Technique}: FAILED"
	}
}

Write-Host
Write-Host "${TestsPassed}/${TotalTests} Atomic Tests Passed"

# Write-Error "${TestsPassed}/${TotalTests} Atomic Tests Passed" -ErrorAction Stop
