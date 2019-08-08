# BLUESPAWN

## What it does
BLUESPAWN helps blue teams monitor Windows systems in real-time against active attackers by detecting anomalous activity

## Why we made BLUESPAWN
We've created and open-sourced this for a number of reasons which include the following:
* **Move Faster**: We wanted tooling specifically designed to quickly identify malicious activity on a system
* **Know our Coverage**: We wanted to know exactly what our tools could detect and not rely on blackbox software as much (ie AV programs). This approach will help us to better focus our efforts on specific lines of effort and have confidence in the status of others.
* **Better Understanding**: We wanted to better understand the Windows attack surface in order to defend it better
* **More Open-Source Blue Team Software**: While there are many open-source Red Team Tools out there, the vast majority of some of the best Blue Team tools are closed-source (ie, AVs, EDRs, SysInternals, etc). We shouldn't need to rely on security through obscurity to prevent malicious actors (obviously very difficult, but something to strive for!)
* **Demonstrate Features of Windows API**: We combed through a ton of Microsoft Documentation, StackOverflow Answers, and more to create this. Hopefully others may find some of the code useful.

## Coverage of MITRE ATT&CK
Visit [this map](https://ion28.github.io/BLUESPAWN/#layerURL=https%3A%2F%2Fion28.github.io%2FBLUESPAWN%2Fassets%2Fcoverage.json) to see current coverage capabilities

## Lines of Effort
BLUESPAWN consists of 5 major modules as listed below. Several of these modules have submodules (which may not be created in the codebase yet) as listed below and all are in varying stages of planning, research, and development.
* Hunt
    * Configuration & Settings
    * File System
    * Hunts
    * Processes
* Monitor
    * ETW
    * File Monitor
    * Process Monitor
    * Registry Monitor
    * User Hooking
* React
    * Reactions
* BLUESPAWN (Program main)
* Logging

## Project Authors
Made with love by the UVA Cyber Defense Team Windows Group
* Jake Smith ([Github](https://github.com/ION28), [Twitter](https://twitter.com/jtsmith282))
* Calvin Krist ([Github](https://github.com/CalvinKrist), [Twitter](https://twitter.com/CalvinKrist))
* Jack McDowell ([Github](https://github.com/jnmcd/))
* Will Mayes ([Github](https://github.com/wtm99), [Twitter](https://twitter.com/will_mayes99))

## Contributors
Thanks to all of the folks listed below for their contributions to BLUESPAWN!
* Your name here!

Want to help? Take a look at the current issues, add ideas for new features, write some code, and create a pull request!

## Special Thanks
We would like to provide a special thank you to the following projects that have helped us to build BLUESPAWN:
* The [MITRE's ATT&CK Project](https://attack.mitre.org/) which has put together an amazing framework for which to consider, document, and categorize attacker tradercraft.
* Microsoft's documentation and examples on the Windows API
* The Japan Computer Emergency Response Team (JPCERT)'s [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/) for its documentation of attacker behavior and correlation with detection opportunities.
