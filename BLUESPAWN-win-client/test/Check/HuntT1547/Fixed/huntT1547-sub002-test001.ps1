$passed = $true
if (Test-Path "C:\Windows\System32\T1547002001.dll"){
    Write-Output "Hunt-T1547-Sub002-Test001: File not removed"
    $passed = $false;
}
return $passed