$passed = $true
if (Test-Path "C:\inetpub\wwwroot\T1505003001.php"){
    Write-Output "Hunt-T1505-Sub003-Test001: File not deleted"
    $passed = $false
}
return $passed