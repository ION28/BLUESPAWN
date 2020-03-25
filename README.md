# BLUESPAWN

[![BLUESPAWN client build](https://github.com/ION28/BLUESPAWN/workflows/BLUESPAWN%20client%20build/badge.svg)](https://github.com/ION28/BLUESPAWN/actions) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/d070613d09404e14b47f69147a99064e)](https://www.codacy.com/manual/ION28/BLUESPAWN?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ION28/BLUESPAWN&amp;utm_campaign=Badge_Grade) ![Version](https://img.shields.io/github/v/release/ION28/BLUESPAWN?include_prereleases) ![License](https://img.shields.io/github/license/ION28/BLUESPAWN) ![Platform](https://img.shields.io/badge/platform-win--32%20%7C%20win--64-lightgrey) ![Operating System](https://img.shields.io/badge/os-Windows%207%2F08%2B-blue)

## Our Mission
BLUESPAWN helps blue teams monitor Windows systems in real-time against active attackers by detecting anomalous activity

## What is BLUESPAWN
BLUESPAWN is an **active defense** and **endpoint detection and response tool** which means it can be used by defenders to quickly **detect**, **identify**, and **eliminate** malicious activity and malware across a network.

## Why we made BLUESPAWN
We've created and open-sourced this for a number of reasons which include the following:

* **Move Faster**: We wanted tooling specifically designed to quickly identify malicious activity on a system
* **Know our Coverage**: We wanted to know exactly what our tools could detect and not rely on blackbox software as much (ie AV programs). This approach will help us to better focus our efforts on specific lines of effort and have confidence in the status of others.
* **Better Understanding**: We wanted to better understand the Windows attack surface in order to defend it better
* **More Open-Source Blue Team Software**: While there are many open-source Red Team Tools out there, the vast majority of some of the best Blue Team tools are closed-source (ie, AVs, EDRs, SysInternals, etc). We shouldn't need to rely on security through obscurity to prevent malicious actors (obviously very difficult, but something to strive for!)
* **Demonstrate Features of Windows API**: We combed through a ton of Microsoft Documentation, StackOverflow Answers, and more to create this. Hopefully others may find some of the code useful.

## Coverage of MITRE ATT&CK
Visit [this map](https://ion28.github.io/BLUESPAWN/) to see current coverage capabilities

## Try out BLUESPAWN 

> Note: BLUESPAWN is under active *alpha* development, so many features may not work as expected yet and detections may be too narrow scope or generate lots of false positives.

> Note 2: BLUESPAWN is meant to be run by a security professional in most cases and as such, will detect on non-malicious activity sometimes. While BLUESPAWN helps to quickly surface potentially bad things, it expects the user to use the available information to make the final determination.

1. Download the latest release from [this page](https://github.com/ION28/BLUESPAWN/releases)
2. Open an Administrative Command Prompt
3. Run the following command to see the available options
```cmd
.\BLUESPAWN.exe --help
```

### Mitigate Mode
4. Run the following from your Administrative Command Prompt to audit your system for the presence of many security settings
```cmd
.\BLUESPAWN-client-x64.exe --mitigate=audit --log=console
```
![BLUESPAWN in Action-Mitigate](https://user-images.githubusercontent.com/3931697/77474842-2f370380-6dee-11ea-9d31-9392daa0a5da.png)

### Hunt Mode
5. Run BLUESPAWN from the Administrative Command Prompt to hunt for malicious activity on the system
```cmd
.\BLUESPAWN-client-x64.exe --hunt -l Cursory --log=console,xml --reaction=log
```
![BLUESPAWN in Action-Hunt](https://user-images.githubusercontent.com/3931697/77475483-4a564300-6def-11ea-8faf-151508af73cb.png)

## Lines of Effort
BLUESPAWN consists of 3 major modes as listed below. Several of these modules have submodules (which may not be created in the codebase yet) as listed below and all are in varying stages of planning, research, and development. Additionally, they are supported by a number of other modules.

* **Hunt** (Hunts for evidence of malicious behavior)

* **Mitigate** (Mitigates vulnerabilities by applying security settings)

* **Monitor** (Continuously monitors the system for potentially malicious behavior)

* **User** (Contains program main, IOBase, and other similar functions)

* **Util** (Contains a collection of modules that support core operations)
    * Configurations
    * Event Logs
    * File System
    * Log
    * PEs
    * Processes

## Contact Us
If you have any questions, comments, or suggestions, please feel free to send us an email at <bluespawn@virginia.edu>

## Licensing & Compliance
The core BLUESPAWN code is licensed under [GNU General Public License (GPL) v3.0](https://github.com/ION28/BLUESPAWN/blob/master/LICENSE).

Note that the project integrates several other libraries to provide additional features/detections. One of these is Florian Roth's [signature-base](https://github.com/Neo23x0/signature-base) which is licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](http://creativecommons.org/licenses/by-nc/4.0/). YARA rules from this project are integrated into the standard build without any changes. In order to use BLUESPAWN for any commercial purposes, you must remove everything under the "Non-Commercial Only" line in [this file](https://github.com/ION28/BLUESPAWN/blob/master/BLUESPAWN-client/resources/severe2.yar) and recompile the project.

## Project Authors
Made with :heart: by the UVA Cyber Defense Team Windows Group

* Jake Smith ([Github](https://github.com/ION28), [Twitter](https://twitter.com/jtsmith282))
* Calvin Krist ([Github](https://github.com/CalvinKrist), [Twitter](https://twitter.com/CalvinKrist))
* Jack McDowell ([Github](https://github.com/jnmcd/))
* Will Mayes ([Github](https://github.com/wtm99), [Twitter](https://twitter.com/will_mayes99))
* Grant Matteo ([Github](https://github.com/GrantMatteo))

## Contributors
Thanks to all of the folks listed below for their contributions to BLUESPAWN!

* Alexander Kluth ([Github](https://github.com/alexclooze))

Want to help? Take a look at the current issues, add ideas for new features, write some code, and create a pull request!

## Special Thanks
We would like to provide a special thank you to the following projects that have helped us to build BLUESPAWN:

* Github's support of open-source projects, especially the ability for unlimited use Github Actions
* Microsoft's documentation and examples on the Windows API
* The Department of Defense's Defense Information Systems Agency (DISA) for their great work in publishing STIGs and various other technical security guidance for Windows.
* [@hasherezade](https://github.com/hasherezade)'s [PE Sieve](https://github.com/hasherezade/pe-sieve), which currently manages our process analytics
* VirusTotal's [YARA](https://github.com/VirusTotal/yara) Project which we use to scan data for malicious identifiers
* The [Yara Rules Project](https://twitter.com/yararules)'s [Rules](https://github.com/Yara-Rules/rules) repository which contains a large collection of open-source YARA rules
* [@Neo23x0](https://github.com/Neo23x0)'s open-source [signature-base](https://github.com/Neo23x0/signature-base) project which contains a large collection of YARA rules
* The [MITRE's ATT&CK Project](https://attack.mitre.org/) which has put together an amazing framework for which to consider, document, and categorize attacker tradercraft
* Red Canary's [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) and [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) Projects which have been incredibly useful in helping to test the detections we are building
* Amazon's [Open Source at AWS Initiative](https://aws.amazon.com/opensource/) who has provided our team some AWS promotional credits to help us reserach and test BLUESPAWN better
* The [NSA Cybersecurity Directorate](https://github.com/nsacyber)'s Windows [Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance)
* [Sean Metcalf](https://twitter.com/PyroTek3)'s Active Directory Security blog [ADSecurity](https://adsecurity.org/)
* [@op7ic](https://github.com/op7ic)'s [EDR-Testing-Script](https://github.com/op7ic/EDR-Testing-Script) Project
* The Japan Computer Emergency Response Team (JPCERT)'s [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/) for its documentation of attacker behavior and correlation with detection opportunities
* [@jarro2783](https://github.com/jarro2783)'s [cxxopts](https://github.com/jarro2783/cxxopts) which we use to parse command line arguments
* [@leethomason](https://github.com/leethomason)'s [tinyxml2](https://github.com/leethomason/tinyxml2) library which we use to output scan information to XML
