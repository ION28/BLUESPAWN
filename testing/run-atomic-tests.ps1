IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')

Install-AtomicRedTeam -getAtomics -verbose

Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Test Parameters
$T1546010Args = @{ "registry_file" = "C:\AtomicRedTeam\atomics\T1546.010\src\T1546.010.reg" }

Invoke-AtomicTest T1037.001 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1053.005 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1055 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1136.001 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1505.003 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1543.003 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1546.007 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1546.008 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1546.010 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv' -InputArgs $T1546010Args
Invoke-AtomicTest T1546.011 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1546.012 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1546.015 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1547.001 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1547.004 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1547.005 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1562.004 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1569.002 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'


Invoke-AtomicTest T1015 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1037 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1050 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1053 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1055 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1060 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1099 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1100 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1101 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1103 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1136 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1138 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
Invoke-AtomicTest T1183 -ExecutionLogPath 'd:\a\BLUESPAWN\BLUESPAWN\AtomicTestsResults.csv'
