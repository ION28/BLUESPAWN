Using Mitigations
=================

BLUESPAWN has the capability to apply settings to a system in order to make it more secure. This is done through mitigation mode.

What are Mitigations
--------------------

In BLUESPAWN, mitigations refer to general area of security settings that can be applied. For example, ensuring a system has proper auditing or hardening settings for MySQL may be a mitigation. Each mitigation in BLUESPAWN has a name corresponding to either a software to be hardened or a MITRE ATT&CK Mitigation, along with a brief description describing what it does. Each mitigation also has exactly one associated software, either the base OS or another software product. While hardening non-default services may fall under a MITRE ATT&CK mitigation, it is instead given its own BLUESPAWN mitigation.

Mitigations consist of some number policies, which refer to a single setting or change to be applied. For example, a mitigation policy may require that a particular registry value hold a certain value. Each policy may set a minimum or maximum software version for the associated mitigation's software. For example, if one setting is required up until version 5.3, and after that it is deprecated in lieu of another setting, one policy could apply the older setting if the version is below 5.3 and another could apply the newer setting after 5.3. Each mitigation policy also holds an enforcement level, either low, moderate, or high. Unless BLUESPAWN's enforcement level is at least the same level as the policy, it will be treated as not required.

Enforcing and Auditing Mitigations
----------------------------------

BLUESPAWN has two modes in which it can use its mitigations - audit and enforce. In audit mode, BLUESPAWN will scan the system and compare the current system state to that described in the mitigation policies. In enforce mode, BLUESPAWN will scan the system, and anything that doesn't match the requirements of the mitigation policies will be updated. In both modes, the user may specify an enforcement level. Mitigation policies that have a higher enforcement level than the user specified level will be checked, but no changes will be made. Mitigation policies marked as not required are still checked during audit mode, but the report will indicate they were not required.

Configuring Auditing and Enforcement
------------------------------------

If the user wishes for finer granularity choice over which policies should be run, BLUESPAWN offers a JSON customization option. It is recommended that the user generate a default JSON configuration file by using the ``--gen-config`` flag. This flag may be set to one of three values: ``global``, ``mitigations``, and ``mitigation-policies``. The ``global`` value will result in the generated configuration file containing only the default enforcement level for all mitigations. The ``mitigations`` value will result in the generated configuration file containing the default enforcement level for all mitigations as well as a separate enforcement level for each mitigation. Finally, the ``mitigation-policies`` value will result in the generated configuration file holding everything from the ``mitigations`` value in addition to all individual mitigation policies, allowing a user to set them as required or not individually. In all cases, the generated configuration file will enforce no policies until it is edited. The resulting JSON will be saved to ./bluespawn-mitigation-config.json, **overwriting any existing file with the same name**.

Some example JSON configuration files are below. The following configuration will result in all mitigations being run at the moderate enforcement level.

.. code-block:: JSON

   {
       "default-enforcement-level": "moderate"
   }

This configuration will result in all mitigations being run at the moderate enforcement level, except for M1025, which will instead be run at high

.. code-block:: JSON

   {
       "default-enforcement-level": "moderate"
       "mitigations": [
           {
               "description": "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures",
               "enforcement-level": "high",
               "name": "M1025 - Privileged Process Integrity"
           }
       ]
   }

This configuration will result in all mitigations being run at the moderate enforcement level, except for M1025, which will instead be run at high. However, mitigation "Run LSA as PPL" will not be enforced at all.

.. code-block:: JSON

   {
       "default-enforcement-level": "moderate"
       "mitigations": [
           {
               "description": "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures",
               "enforcement-level": "high",
               "name": "M1025 - Privileged Process Integrity"
               "overrides": [
                   {
                       "description": "Run the Local Security Authority as a Protected Process Lite, preventing process injection and other attacks on lsass.exe's memory",
                       "enabled": false,
                       "policy-name": "Run LSA As PPL"
                   }
               ]
           }
       ]
   }

Note that while descriptions of the mitigations and policies are present in these files, they are not needed. The configuration generator simply includes them to it is more clear what each mitigation is doing and why it is present. Note that the policy names and mitigation names *are* required.

Defining Custom Mitigations
---------------------------

BLUESPAWN comes prepackaged with a number of mitigations and mitigation policies. However, in the event that a user wishes for BLUESPAWN to be able to provide more hardening capabilities, there are two options. First, create an issue (or a pull request)! We are happy to add mitigations that add value to BLUESPAWN! Alternatively, BLUESPAWN is capable of ingesting mitigations from JSON configuration files with the ``--add-mitigations`` flag. If there are multiple JSON configuration files to add, the ``--add-mitigations`` flag may be used multiple times, once per mitigation file.

An example configuration file defining mitigation M1025 is provided below. This file has been commented with JavaScript comments, but our JSON parsing library does not allow these. If you intend to use this for any purpose, please remove the comments first.

.. code-block:: JSON

   {
     "mitigations": [
       {
         // Required to be unique. This defines the mitigation name.
         "name": "M1025 - Privileged Process Integrity",
   
         // This is not required, but it is highly recommended. A description makes it clear what a mitigation does.
         "description": "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures", 
   
         // Specify the software associated with this mitigation. Note that as mitigations are still in development,
         // automatic software detection for non-windows software is not yet complete. This is required.
         "software": "Windows",
   
         // This specifies the policies that compose this mitigation. This is required.
         "policies": [
           {
             // This tells BLUESPAWN how the policy should be interpreted. This is required.
             // For other options, see the documentation under headers/mitigation/policy
             "policy-type": "registry-value-policy",
   
             // The name of the policy. This should be short. It is required.
             "name": "Run LSA As PPL",
   
             // The description of what the policy does and why it matters. Optional but highly recommended.
             "description": "Run the Local Security Authority as a Protected Process Lite, preventing process injection and other attacks on lsass.exe's memory",
   
             // The minimum enforcement level at which the policy should be run. Generally speaking, low
             // enforcement levels are used when there are little to no negative side effects, moderate when
             // there may be negative side effects, but they are considered normal (i.e. UAC), and high when
             // enforcing the policy may cause problems (i.e. egress filtering)
             "enforcement-level": "moderate",
   
             // The minimum software version. For windows, this is the windows NT major version, followed by
             // the minor version, and optionally the build number. This may be omitted. Note that 
             // max-software-version may also be specified.
             "min-software-version": "6.3",
   
             // Since this is a registry value policy, it is used to apply some change to one or more registry
             // value. A key path is required to select which value. Note that * may be used to match any key
             // i.e. "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\*" matches all
             // keys under interfaces.
             "key-path": "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
   
             // The name of the value for which this policy applies
             "value-name": "RunAsPPL",
   
             // The value of the data to check for with this value
             "data-value": 1,
   
             // The type of the data to check for with this value. This must be REG_SZ, REG_DWORD, REG_MULTI_SZ,
             // or REG_BINARY. 
             "data-type": "REG_DWORD",
   
             // The type of registry value policy. This requires the value to hold the exact data specified
             // For other options, see the documentation under headers/mitigation/policy/RegistryPolicy.h
             "registry-value-policy-type": "require-exact"
           }
         ]
       }
     ]
   }

