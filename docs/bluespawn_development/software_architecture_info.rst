Software Architecture Info
==========================

Key ideas
---------

- Association: Relationship between two detections. Each association holds a weight between 0 and 1. An association of weight 0 means two things are completely unrelated while an association of strength 1 means two things are very closely related.
- Detection: Something that may or may not be malicious. This is represented by a ``Detection`` object. ``Detection`` objects have a couple important fields worth being familiar with. Each of these will be described in terms of a sample detection for a file called ``malware.exe`` located in the ``C:\`` directory.

  - data: This holds information about what is being detected on as well as perhaps reasons why it was detected. In this example, ``data`` would store the file name, the file path, the file association, results of a yara scan on the file, information about signatures on the file, and hashes for the file
  - type: Indicates what type of thing the ``Detection`` is referencing. In this example, ``type`` would be ``DetectionType::FileDetection``
  - DetectionStale: Indicates whether the ``Detection`` accurately reflects the state of the OS. ``Detection``'s may be created for files that have been deleted, processes that have been killed, or other things that are no longer present. In this example, since ``C:\malware.exe`` still exists, ``DetectionStale`` would be false.
  - info: This holds information about scans performed on this ``Detection`` and the associations held by each detection. In this example, ``info`` would indicate with high certainty that ``malware.exe`` is in fact malicious. ``info`` would also indicate that this executable is related to registry keys that point to it.
  - remediator: Not all problems can be fixed the same way. BLUESPAWN has built in capabilities to do things like deleting files or removing registry keys, but sometimes, a specialized solution is needed. For ``Detection`` s that reference something that needs to be fixed rather than removed, a custom remediator can be defined to describe how the ``Detection`` can be remediated. In this example, ``C:\malware.exe`` is malware and would not need a remediator.
  - context: This stores information surrounding the ``Detection`` but not describing the actual ``Detection`` itself. This is things like when the thing referenced by the ``Detection`` was first detected, when the first evidence of its existence was created, which hunt identified it, and any note describing why the ``Detection`` was made. In the example, this would indicate when the file was created, when the file was found, and which hunt identified it.
  - Certainty: Represents the degree of confidence that a detection is malicious. This is part of ``info`` inside of the ``Detection``. ``Certainty`` can be further broken down in to *intrinsic certainty* and *associtivity certainty*.
  - Intrinsic Certainty: Represents the certainty that the specific thing referenced by the detection is malicious in its own regard. In the example of ``malware.exe``, this would be calculated from things like the results of yara scans on the file and whether the file is signed.
  - Associtivity Certainty: Represents certainty derived from associations. In general, if a file and a process are found to be closely related, if one is malicious, chances are the other one is too. This is what's referenced by associativity certainty. In the example, if ``malware.exe`` was found to be loaded in a process that was dumping credentials, ``malware.exe`` would receive a high associtivity certainty.

- Aggressiveness: This is user specified when BLUESPAWN is launched. Higher aggressiveness means longer scans and more false positives, but also a better chance of catching everything. Options are ``Intensive``, ``Normal``, and ``Cursory``.

Hunts
-----

Hunts are the starting point for creation of ``Detection`` s. Hunts are defined to cover one MITRE ATT&CK technique and create ``Detection`` s for anything found to be using the technique maliciously. An example hunt's CPP source is below.

.. code-block:: cpp

   HuntT1013::HuntT1013() : Hunt(L"T1013 - Port Monitors") {
       dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
       dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
       dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
   }

   std::vector<std::shared_ptr<Detection>> HuntT1013::RunHunt(const Scope& scope) {
       HUNT_INIT();

       RegistryKey monitors{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors" };

       for(auto monitor : monitors.EnumerateSubkeys()) {
           if(monitor.ValueExists(L"Driver")) {
               auto filepath{ FileSystem::SearchPathExecutable(monitor.GetValue<std::wstring>(L"Driver").value()) };

               if(filepath && FileScanner::PerformQuickScan(*filepath)) {
                   CREATE_DETECTION(Certainty::Moderate,
                                    RegistryDetectionData{ *RegistryValue::Create(monitor, L"Driver"),
                                                           RegistryDetectionType::FileReference });
               }
           }
       }

       HUNT_END();
   }

   std::vector<std::unique_ptr<Event>> HuntT1013::GetMonitoringEvents() {
       std::vector<std::unique_ptr<Event>> events;

       Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
                                   false, false, true);

       return events;
   }

As you can see, the constructor defines the name of the technique as well as the tactics, categories, and data sources involved. 

More important is the ``RunHunt`` method. Every ``RunHunt`` method should begin with ``HUNT_INIT();``, or in cases where the hunt should only run above a certain aggressiveness, use ``HUNT_INIT_LEVEL([Minimum aggressiveness])``. Each ``RunHunt`` method should also end with ``HUNT_END();``. Inside the hunt, there is plenty of leeway in terms of what can be done. There are two macros defined for creating ``Detection`` s. The first - and far more common - one is ``CREATE_DETECTION``. The first argument of this is the base certainty given to the ``Detection``. The idea behind this is that ``Detection`` s should in some cases receive some degree of certainty simply for where they were found. For example, any ``AppInit_Dll`` should be met with a high degree of skepticism due to how rarely it is used in a benign manner and how commonly it is used maliciously - and therefore should have a high base certainty. This is factored into the intrinsic certainty score. The second is the ``DetectionData`` struct containing information about the detection. See ``detections.h`` for more information about how this should be created. In the other ``Detection`` creation macro, ``CREATE_DETECTION_WITH_CONTEXT``, allows developers to specify detail about the detection. This can include a custom context (needed if a note or FirstEvidenceTime is to be added), a remediator, and an indicator of whether or not the detection is stale.

The last method in every hunt is ``GetMonitoringEvents``. This method should return a vector of unique pointers to ``Event`` s, specifying when the hunt should be rerun during monitor mode. 

Monitor Mode
------------

Monitor mode is in a more primitive state than hunt mode. As it stands now, each hunt defines its triggers in ``GetMonitoringEvents``. Then whenever any log, file, or registry key specified by the hunt gets updated, the hunt gets rerun. 

