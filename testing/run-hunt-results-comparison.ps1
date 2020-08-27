$tests = Import-Csv .\AtomicTestsResults.csv
[xml]$results = Get-Content .\BLUESPAWNHuntResults.xml

$TotalTests = 0
$TestsPassed = 0

ForEach($Technique in ($tests | ForEach-Object { $_.Technique } | get-unique)) {
	$TotalTests += 1

	$TechniqueTests = $tests | Where-Object { $_.Technique -eq $Technique }
	$TechniqueTestCount = (($TechniqueTests | Measure).count)

    $TechniqueMajor = $Technique.split(".")[0]
    $TechniqueMinor = $Technique.split(".")[1]
	
	$TechniqueResults = $results.bluespawn.detection."associated-hunts" | Where-Object { $_.hunt -like "$TechniqueMajor*" -and $_.hunt -like [string]"*$TechniqueMinor*" }

	$TechniqueDetectionCount = (($TechniqueResults | Measure).count)
	
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
