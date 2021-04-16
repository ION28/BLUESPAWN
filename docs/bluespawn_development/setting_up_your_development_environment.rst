Setting up your Development Environment
=======================================

Environment Requirements
------------------------

You *may* be able to get this to run on different OSs / environments, but we strongly recommend using the below

- Windows 10
- Visual Studio 2019

Cloning the repository and downloading dependencies
---------------------------------------------------

Clone the repo and install the submodules

.. code-block:: bash

   git clone https://github.com/ION28/BLUESPAWN.git
   cd BLUESPAWN
   git submodule update --init --recursive

In a **administrative** command prompt (not PowerShell) window in the BLUESPAWN main folder, run the following to install the project's dependencies. It is recommended to add this folder to Windows Defender's or another AV product's folders exclusion list.

NOTE: This is going to take at least 25 min probably, but once this is done, you'll likely never need to rerun this.

.. code-block:: cmd

   cd vcpkg
   .\bootstrap-vcpkg.bat
   .\vcpkg.exe install @../vcpkg_response_file.txt
   .\vcpkg.exe integrate install
   cd ..

Working on code
---------------

Checkout a new branch (off of develop)

.. code-block:: bash

   git checkout develop
   git checkout -b new-branch-name

Open Visual Studio, and then open the solution file, BLUESPAWN.sln

