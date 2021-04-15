Project Roadmap
===============

Project Organization
--------------------

- Encourage more people to get involved in the development
- :strike:`Wiki pages`
- :strike:`Make docs easy to find`
- [in progress] More Discord development sessions
- [in progress] Contribution guidelines


Client Windows
--------------

Short Term (~1 month)
^^^^^^^^^^^^^^^^^^^^^

- [in progress, testing phase] `Scan Mode / Multithreading / Internals Overhaul <https://github.com/ION28/BLUESPAWN/pull/352>`_
- :strike:`Strict adherence to code style guidelines (clang-format)`
- `Add JSON Sink <https://github.com/ION28/BLUESPAWN/issues/353>`_
- :strike:`Clangformat package for styling`
- `Add mitigation for installing Sysmon <https://github.com/ION28/BLUESPAWN/issues/354>`_ (use winhttp, see message from Jack)
- `Update BLUESPAWN to utilize new MITRE ATT&CK Subtechniques <https://github.com/ION28/BLUESPAWN/issues/350>`_

Medium Term (2 - 6 months)
^^^^^^^^^^^^^^^^^^^^^^^^^^

- Scan mode improvements
- Modify hunts to contextualize detections
- More Utilities

  - Scheduled Tasks
  - CollectInfo to gather local system info (ie to record stuff like hostname, ip, etc) and add functions (ie to determine if running on a DC) (update T1136 when this is done)

- Begin agent DLL
- Add ``--config`` option with YML
- Add Network Sink
- More and improved hunts & mitigations
- Stronger Atomic Red Team / other testing

Long Term (6+ months)
^^^^^^^^^^^^^^^^^^^^^

- Alice in Kernelland
- BaaS (Bluespawn as a [Windows] Service)
- Add support for AMSI
- More and improved hunts & mitigations
- ETW using krabsetw, see https://github.com/pathtofile/Sealighter

Client Linux
------------

Short Term  (~1 month)
^^^^^^^^^^^^^^^^^^^^^^

- Initial POC version

Medium Term (2 - 6 months)
^^^^^^^^^^^^^^^^^^^^^^^^^^

Long Term (6+ months)
^^^^^^^^^^^^^^^^^^^^^

[BELOW ROADMAP IS SIGNIFICANTLY OUT OF DATE] Server
---------------------------------------------------

### Short Term (~1 month)
^^^^^^^^^^^^^^^^^^^^^^^^^

- Meet to discuss ELK vs other options with Wasabi and David

  - Alternative: support our own API that forwards to a back end, (replace logstash ?)
    
    - Create our own parser for BLUESPAWN logs
    - Other people can write adapters for other log types

  - At the least: be backend agnostic

- Get SSL for Logstash
- Get WinLogBeats set up with working SSL and Filebeats with BS logs

  - Incorporate into Ansible playbook

- Create 'First Log In' scripts to enforce proper credentials and SSL keys
- Document tech stack and general server architecture
- Change Ansible script to use autorun keys instead of service installation

Medium Term (2 - 6 months)
^^^^^^^^^^^^^^^^^^^^^^^^^^

- Create Logstash parsers to support MITRE stuff

  - More unified BLUESPAWN logging format

- Create basic web gui
- Continue to document scripts and tech stack
- Speak with more stakeholders and professional security admins and active threat hunters about EDRs and the features they need

  - Create feature priority list

- Create simple endpoint control and management

  - Refresh credentials
  - Run specific hunts
  - Deploy mitigations
  - Listing machine info

- Ensure the server is deployable to existing architecture

  - Support existing ELK stuff
  - Support other backends

- Create basic analysis plugins

  - Integrate Sigma rules
  - Create Sigma rules for bluespawn?

- Support more deployment options (design to be easily downloadable from the server)

  - GPO
  - Batch scripts / installers
  - API

Long Term (6+ months)
^^^^^^^^^^^^^^^^^^^^^

- Support more advanced endpoint control

  - Support remediation options from the web server
  - Support firewall configuration from the web server

- Create more analysis plugins
- Support users, groups, and other administration type use cases

  - Extend the backend’s users, eg kibana

- Use parsed MITRE tags to recreate attacks
- Report generation and custom display / views that can be saved to a specific URL

  - For example, go to ``myserver/report1`` to see a search and visualization of brute force login attacks

- Ensure server can scale to most corporate performance needs

  - Kubernetes, support multiple ELK nodes, load balancers, message queue






