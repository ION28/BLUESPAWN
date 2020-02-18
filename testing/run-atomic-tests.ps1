IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/execution-frameworks/Invoke-AtomicRedTeam/install-atomicredteam.ps1'); Install-AtomicRedTeam -verbose

Import-Module C:\AtomicRedTeam\execution-frameworks\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psm1

Invoke-AtomicTest T1004 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1015 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1037 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1050 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1055 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1060 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1099 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1100 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1101 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1103 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1136 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1138 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1183 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
