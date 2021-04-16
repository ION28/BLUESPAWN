Getting Started
===============

Download BLUESPAWN binary `here <https://github.com/ION28/BLUESPAWN/releases>`_, then open an Administrative Command Prompt and navigate to where you downloaded the binary.

Hunt Mode
---------

Perform a hunt for malicious activity on a system by looking for evidence of over 25 different MITRE ATT&CK Techniques including Process Injection (T1055), Run Keys (T1060), and other popular malware techniques.

.. code-block:: cmd

   # Run a basic hunt
   BLUESPAWN-client-x64.exe --hunt -a Normal --react=log --log=console

This command will run all of the implemented hunts at the Normal level. These hunts will print information about anything suspicious they find, but will not actively do anything about them.

Modifiers / Additional Arguments
--------------------------------

You can pass some additional arguments to extend or change how BLUESPAWN operates in Hunt mode.
- ``--hunts=TXXX,TXXX`` : pass a comma separated list of MITRE ATT&CK Techniques to only hunt for specific techniques
- ``--exclude-hunts=TXXX,TXXX`` : pass a comma separated list of MITRE ATT&CK Techniques to EXCLUDE from a hunt. This runs every implemented hunt except the ones you specify
- ``-a Normal, --aggressiveness=Normal`` : pass either Cursory, Normal, or Intensive to specify how invasive to check. Generally hunts take longer & generate more false positives as the level increases.
- ``-r log,carve-memory, --react=log,carve-memory`` : pass a comma separated list of the available reactions listed below to customize how BLUESPAWN can respond to detected threats
  - ``log`` : default, records the detection
  - ``remove-value`` : removes a detected registry value
  - ``suspend`` : suspends a detected process
  - ``carve-memory`` : temporarily suspends the process and effectively removes all malicious threads before resuming the process. Useful for responding to process injection (T1055) as this only removes the malware without killing the entire process
  - ``delete-file`` : deletes any detected malware files
  - ``quarantine-file`` : denies ``Everyone`` access to the file
- ``--log=console,xml`` : pass a comma separated list of available sinks to log results to. Options are ``console`` (writes to screen) and ``xml`` (writes to an xml file in the current directory)


Monitor Mode
------------

Set BLUESPAWN in monitor mode to continuously watch for any evidence of malware on a system. This mode works by monitoring sensitive registry keys, files, and more that malware is known to abuse. Then, when something changes, it runs the associated hunt and triggers detections as needed.

.. code-block:: cmd

   # Monitor the system for threats
   BLUESPAWN-client-x64.exe --monitor -a Normal --react=log --log=console,xml

Modifiers / Additional Arguments
--------------------------------

All of the aforementioned arguments in hunt mode work in monitor mode. 

Mitigate Mode
-------------

Run BLUESPAWN in mitigate mode to audit or enforce a variety of DoD STIG settings or MITRE Mitigations that can help to enhance the security posture of a system.

.. code-block:: cmd

   # Audit the current system against available STIG settings/Mitigations 
   BLUESPAWN-client-x64.exe --mitigate --action=audit

   # Enforce compliance of the current system against available STIG settings/Mitigations
   BLUESPAWN-client-x64.exe --mitigate --action=enforce

Other commands
--------------

Get information about available commands

.. code-block:: cmd

   BLUESPAWN-client-x64.exe --help

