![BLUESPAWN-logo2-temp](https://user-images.githubusercontent.com/3931697/89133344-0e439500-d4e9-11ea-992f-6ae8ebe66177.png)

# BLUESPAWN

![Version](https://img.shields.io/github/v/release/ION28/BLUESPAWN?include_prereleases) ![License](https://img.shields.io/github/license/ION28/BLUESPAWN?color=yellow) ![Platform](https://img.shields.io/badge/platform-x86%20%7C%20x64-lightgrey) ![Operating System](https://img.shields.io/badge/os-Windows%207%2F08%2B-blue) [![Discord](https://img.shields.io/discord/713926524167913544?color=blueviolet&label=Discord&logo=Discord&logoColor=white)](https://discord.gg/JMxPPfZ)

#### Code Status

[![Win Client build](https://github.com/ION28/BLUESPAWN/workflows/BLUESPAWN-win-client%20build/badge.svg)](https://github.com/ION28/BLUESPAWN/actions) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/d070613d09404e14b47f69147a99064e)](https://www.codacy.com/manual/ION28/BLUESPAWN?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ION28/BLUESPAWN&amp;utm_campaign=Badge_Grade) ![Last Commit](https://img.shields.io/github/last-commit/ION28/BLUESPAWN/develop)

## Our Mission
BLUESPAWN helps blue teams monitor systems in real-time against active attackers by detecting anomalous activity

## What is BLUESPAWN
BLUESPAWN is an **active defense** and **endpoint detection and response tool** which means it can be used by defenders to quickly **detect**, **identify**, and **eliminate** malicious activity and malware across a network.

## Get Involved & Contribute to the project
Want to help make BLUESPAWN even more effective at locating and stopping malware? Join us on [the BLUESPAWN Discord Server](https://discord.gg/JMxPPfZ) and help with development or even just suggest a feature or report a bug. No experience required - there's no better way to learn about development or security than by just jumping right in!

If you'd like to help contribute code, you can get started by checking out our wiki page on [setting up your development environment](https://github.com/ION28/BLUESPAWN/wiki/Setting-up-your-Development-Environment). Please feel free to reach out to us in Discord if you run into any problems getting set up! We generally track bugs and new features through Issues and coordinate in chat when doing any development work.

## Why we made BLUESPAWN
We've created and open-sourced this for a number of reasons which include the following:

* **Move Faster**: We wanted tooling specifically designed to quickly identify malicious activity on a system
* **Know our Coverage**: We wanted to know exactly what our tools could detect and not rely on blackbox software as much (ie AV programs). This approach will help us to better focus our efforts on specific lines of effort and have confidence in the status of others.
* **Better Understanding**: We wanted to better understand the Windows attack surface in order to defend it better
* **More Open-Source Blue Team Software**: While there are many open-source Red Team Tools out there, the vast majority of some of the best Blue Team tools are closed-source (ie, AVs, EDRs, SysInternals, etc). We shouldn't need to rely on security through obscurity to prevent malicious actors (obviously very difficult, but something to strive for!)
* **Demonstrate Features of Operating System APIs**: We combed through a ton of Microsoft Documentation, StackOverflow Answers, and more to create this. Hopefully others may find some of the code useful.

## Coverage of MITRE ATT&CK
Visit [this map](https://bluespawn.cloud/coverage/) to see current coverage capabilities

## Try out BLUESPAWN 

> Note: BLUESPAWN is under active *alpha* development, so many features may not work as expected yet and detections may be too narrow scope or generate lots of false positives.

> Note 2: BLUESPAWN is meant to be run by a security professional in most cases and as such, will detect on non-malicious activity sometimes. While BLUESPAWN helps to quickly surface potentially bad things, it expects the user to use the available information to make the final determination.

0. Check out the [Wiki pages](https://github.com/ION28/BLUESPAWN/wiki) to learn more about the available [command line options](https://github.com/ION28/BLUESPAWN/wiki/Getting-Started), [examples](https://github.com/ION28/BLUESPAWN/wiki/Examples), and more.
1. Download the latest release from [this page](https://github.com/ION28/BLUESPAWN/releases)
2. Open an Administrative Command Prompt
3. Run the following command to see the available options
```cmd
.\BLUESPAWN-client-x64.exe --help
```

### Mitigate Mode
4. Run the following from your Administrative Command Prompt to audit your system for the presence of many security settings
```cmd
.\BLUESPAWN-client-x64.exe --mitigate --action=audit
```
![BLUESPAWN in Action-Mitigate](https://user-images.githubusercontent.com/3931697/89669848-25e69900-d8ae-11ea-836d-1618d7377211.png)

### Hunt Mode
5. Run BLUESPAWN from the Administrative Command Prompt to hunt for malicious activity on the system
```cmd
.\BLUESPAWN-client-x64.exe --hunt -a Cursory --log=console,xml
```
![BLUESPAWN in Action-Hunt](https://user-images.githubusercontent.com/3931697/89669912-4878b200-d8ae-11ea-967b-03318468d711.png)

### Monitor Mode
6. Run BLUESPAWN from the Administrative Command Prompt to monitor for malicious activity on the system
```cmd
.\BLUESPAWN-client-x64.exe --monitor -a Cursory --log=console,xml
```
![BLUESPAWN in Action-Monitor](https://user-images.githubusercontent.com/3931697/89670008-752cc980-d8ae-11ea-8490-1e0473d5f3c6.png)


## Lines of Effort
BLUESPAWN consists of 3 major modes as listed below. Several of these modules have submodules (which may not be created in the codebase yet) as listed below and all are in varying stages of planning, research, and development. Additionally, they are supported by a number of other modules.

* **Hunt** (Hunts for evidence of malicious behavior)

* **Mitigate** (Mitigates vulnerabilities by applying security settings)

* **Monitor** (Continuously monitors the system for potentially malicious behavior)

* **Scan** (Used to assess items identified by hunts and make a decision whether or not it is suspicious/malware)

* **User** (Contains program main, IOBase, and other similar functions)

* **Util** (Contains a collection of modules that support core operations)
    * Configurations
    * Event Logs
    * File System
    * Log
    * PEs
    * Processes

## Talks, Publications, and Other Mentions

Here are some of the places you may have heard about the project :)

[![DEFCON 28 Blue Team Village](https://user-images.githubusercontent.com/3931697/89669226-11ee6780-d8ad-11ea-9361-fba4cb92c97c.png)](https://github.com/ION28/BLUESPAWN/blob/master/docs/media/Defcon28-BlueTeamVillage-BLUESPAWN-Presentation.pdf)

DEFCON 28 Blue Team Village - [Overview](https://cfc.blueteamvillage.org/call-for-content-2020/talk/NCWJFG/), [Slides](https://github.com/ION28/BLUESPAWN/blob/master/docs/media/Defcon28-BlueTeamVillage-BLUESPAWN-Presentation.pdf)

National Collegiate Cyber Defense Competition, 2020 Red Team Debrief - [Youtube](https://youtu.be/UsZhMRMGLMA?t=3582)

BLUESPAWN Research Paper at UVA - [Paper](https://libraetd.lib.virginia.edu/downloads/1j92g810n?filename=Smith_Jacob_Technical_Report.pdf), DOI 10.18130/v3-b1n6-ef83

## Contact Us
If you have any questions, comments, or suggestions, please feel free to send us an email at <bluespawn@virginia.edu> or message us in [the BLUESPAWN Discord Server](https://discord.gg/JMxPPfZ).

## Licensing & Compliance
The core BLUESPAWN code is licensed under [GNU General Public License (GPL) v3.0](https://github.com/ION28/BLUESPAWN/blob/master/LICENSE).

Note that the project integrates several other libraries to provide additional features/detections. One of these is Florian Roth's [signature-base](https://github.com/Neo23x0/signature-base) which is licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](http://creativecommons.org/licenses/by-nc/4.0/). YARA rules from this project are integrated into the standard build without any changes. In order to use BLUESPAWN for any commercial purposes, you must remove everything under the "Non-Commercial Only" line in [this file](https://github.com/ION28/BLUESPAWN/blob/master/BLUESPAWN-win-client/resources/severe2.yar) and recompile the project.

## Project Authors
Made with :heart: by the UVA Cyber Defense Team and the other awesome people in the core dev team listed below

* Jake Smith ([Github](https://github.com/ION28), [Twitter](https://twitter.com/jtsmith282))
* Jack McDowell ([Github](https://github.com/Jack-McDowell))
* Calvin Krist ([Github](https://github.com/CalvinKrist), [Twitter](https://twitter.com/CalvinKrist))
* Will Mayes ([Github](https://github.com/wtm99), [Twitter](https://twitter.com/will_mayes99))
* David Smith ([Github](https://github.com/DavidSmith166))
* Aaron Gdanski ([Github](https://github.com/agski331))
* Grant Matteo ([Github](https://github.com/GrantMatteo))

## Contributors
Thanks to all of the folks listed below for their contributions to BLUESPAWN!

* Alexander Kluth ([Github](https://github.com/akluth))
* Yehuda Hido Cohen ([Github](https://github.com/mryode))

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
* Geoff Chappell's [website on Windows components](https://www.geoffchappell.com/index.htm)
* [Matt Graeber](https://twitter.com/mattifestation)'s amazing Windows Security research including his [Subverting Trust in Windows Paper](https://www.specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
* [@op7ic](https://github.com/op7ic)'s [EDR-Testing-Script](https://github.com/op7ic/EDR-Testing-Script) Project
* The Japan Computer Emergency Response Team (JPCERT)'s [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/) for its documentation of attacker behavior and correlation with detection opportunities
* [@jarro2783](https://github.com/jarro2783)'s [cxxopts](https://github.com/jarro2783/cxxopts) which we use to parse command line arguments
* [@leethomason](https://github.com/leethomason)'s [tinyxml2](https://github.com/leethomason/tinyxml2) library which we use to output scan information to XML
