#define PY_SSIZE_T_CLEAN
#define Py_BUILD_CORE_MODULE

#include <Windows.h>

#include "Python.h"

HMODULE bluespawnLibrary = NULL;

PyDoc_STRVAR(SetLogSinks_doc,
             "Tells bluespawn to send logs to the specified sinks. For sinks that write to files, "
             "logdir can be used to specify the directory to which the logs are saved. Available sinks: console, "
             "xml, debug, and json. For v0.1, this adds sinks rather than setting the ones to be used.\n"
             "Arguments:\n\tsinks: List of strings. Optional, defaults to [\"cursory\"]\n\toutdir: String specifity "
             "the path of the directory to which xml and json sinks should save log files.");
PyDoc_STRVAR(AddDetectionSink_doc,
             "Will be used to specify a new place that reactions should be sent to."
             "This is not supported in v0.1\n"
             "Arguments:\n\tsink: Instance of DetectionSink. Required.");
PyDoc_STRVAR(SetAggressiveness_doc,
             "Tells bluespawn the aggressiveness at which hunts and scans should be run. The "
             "following levels are available: Cursory, Normal, and Intensive. As aggressiveness is increased, so will "
             "false positive rate and runtime. However, more will be scanned and more true positives will also be "
             "picked up. Note that WaitForTasks should be called before changing aggressiveness.\n"
             "Arguments:\n\taggressiveness: int - 1 (cursory), 2 (normal), or 3 (intensive). Required.");
PyDoc_STRVAR(RunHunts_doc,
             "Instructs bluespawn to begin running the specified hunts. Hunts are specified by their "
             "MITRE ATT&CK Technique ID (i.e. T1553). Hunts will be run asynchronously; to receive results, first"
             "call WaitForTasks() then GetAllDetections(). Detections will also be sent to detection sinks.\n"
             "Arguments:\n\tinclude: List of strings specifying hunts to run. If empty, includes all hunts. Optional, "
             "defaults to empty.\n\texclude: List of strings specifying hunts not to run. Optional, defaults to empty");
PyDoc_STRVAR(Monitor_doc,
             "Instructs bluespawn to begin monitoring the specified hunts. Hunts are specified by their "
             "MITRE ATT&CK Technique ID (i.e. T1553). Detections will be sent to the detection sinks specified by "
             "AddDetectionSinks. Since detection sinks are not supported in v0.1, this should not be used.\n"
             "Arguments:\n\tinclude: List of strings specifying hunts to monitor. If empty, includes all hunts. "
             "Optional; defaults to empty list.\n\texclude: List of strings specifying hunts not to run. Optional, "
             "defaults to empty list");
PyDoc_STRVAR(SetReactions_doc,
             "Adds reactions bluespawn should take upon finding a detection. Note that in v0.1, "
             "all reactions will be taken without user confirmation. Given that bluespawn will detect many false "
             "positives, it is recommended that no detections be added. Available reactions are: carve-memory, "
             "suspend, delete-file, quarantine-file, and remove-value.\n"
             "Arguments:\n\reactions: List of strings, where is the name of a reaction. Required.");
PyDoc_STRVAR(AddMitigations_doc,
             "Adds mitigations to bluespawn, which will be run when RunMitigations is called with "
             "the appropriate config. The mitigations passed in must be in the appropriate JSON format. For an "
             "example, see the mitigations.json file packaged with bluespawn.\n"
             "Arguments:\n\tmitigations: JSON-encoded mitigations, passed as a string. Required.");
PyDoc_STRVAR(RunMitigations_doc,
             "Runs all mitigations in bluespawn at or below the provided level, either in audit "
             "or enforcement mode. Returns a dict of mitigation names mapping to dicts of mitigation policies mapping "
             "to the results of the mitigation policy enforcement or audit. \n"
             "Arguments:\n\tlevel: enforcement level, 1 (low), 2 (moderate), or 3 (high), passed an int. Optional; "
             "defaults to 2.\n\tenforce: True to enforce mitigations or False to audit. Optional; defaults to True");
PyDoc_STRVAR(RunMitigationsWithConfig_doc,
             "Runs all mitigations in bluespawn meeting the requirements in the "
             "provided config, either in audit or enforcement mode. Returns a dict of mitigation names mapping to "
             "dicts of mitigation policies mapping to the results of the mitigation policy enforcement or audit. \n"
             "Arguments:\n\tconfig: string containing a json mitigation configuration. Must meet the specification on "
             "the BS wiki.\n\tenforce: True to enforce mitigations or False to audit. Optional; defaults to True");
PyDoc_STRVAR(WaitForTasks_doc,
             "Many of bluespawn's hunting, monitoring, and scanning features operate asynchronously. "
             "WaitForTasks() tells bluespawn to ensure all asynchronous tasks are completed before returning. This is "
             "intended to be used before changing aggressiveness, running more hunts, reading the message buffer, or "
             "retriving detections.\n"
             "Arguments: None");
PyDoc_STRVAR(GetAllDetections_doc,
             "Waits for all active scans to finish, then retrieves a list of all detections "
             "from when bluespawn started until the function was called. Any detection returned should supercede "
             "detections returned from previous calls to GetAllDetections. It is recommended that WaitForTasks() be "
             "called before GetAllDetections to ensure that there are no outstanding hunts which may identify more "
             "detections.\n"
             "Arguments: None");
PyDoc_STRVAR(RetrieveMessages_doc,
             "All messages bluespawn would normally send to the console are instead sent to an "
             "internal message buffer. RetrieveMessages() retrieves the contents of this buffer and returns them as a "
             "list of strings. Note that some messages are sent in multiple parts. Newlines are already added in and "
             "should not be automatically added between messages.\n"
             "Arguments: None");
PyDoc_STRVAR(ScanProcess_doc,
             "Scans a specified process, returning a detection if any BLUESPAWN detected anything anomalous. Otherwise"
             " returns None.\n"
             "Arguments:\n\tpid: int specified the PID of the process to scan. Required.");
PyDoc_STRVAR(ScanFile_doc,
             "Scans a specified file, returning a detection if any BLUESPAWN detected anything anomalous. Otherwise "
             "returns None.\n"
             "Arguments:\n\tfile_path: The path to the file to scan, passed as a string. Required.");
PyDoc_STRVAR(ScanFolder_doc,
             "Scans all files in a specified folder, returning a list of any detections BLUESPAWN found. "
             "Arguments:\n\tfolder_path: The path to the folder to scan, passed as a string. Required.");

typedef PyObject* (*PyFunc)(PyObject* self, PyObject* args, PyObject* keywds);

#define PY_METHOD_DEF(name)                                                            \
    PyObject* name(PyObject* self, PyObject* args, PyObject* keywds) {                 \
        return ((PyFunc) GetProcAddress(bluespawnLibrary, #name))(self, args, keywds); \
    }

#define PY_METHOD_EXPORT(name) \
    { #name, (PyCFunction) name, METH_VARARGS | METH_KEYWORDS, name##_doc }

#define PASS_PY_FUNC(name) &name

PY_METHOD_DEF(AddDetectionSink)
PY_METHOD_DEF(SetLogSinks)
PY_METHOD_DEF(SetAggressiveness)
PY_METHOD_DEF(RunHunts)
PY_METHOD_DEF(Monitor)
PY_METHOD_DEF(SetReactions)
PY_METHOD_DEF(AddMitigations)
PY_METHOD_DEF(RunMitigations)
PY_METHOD_DEF(RunMitigationsWithConfig)
PY_METHOD_DEF(WaitForTasks)
PY_METHOD_DEF(GetAllDetections)
PY_METHOD_DEF(RetrieveMessages)
PY_METHOD_DEF(ScanProcess)
PY_METHOD_DEF(ScanFile)
PY_METHOD_DEF(ScanFolder)

PyMethodDef methods[] = {
    PY_METHOD_EXPORT(AddDetectionSink),
    PY_METHOD_EXPORT(SetLogSinks),
    PY_METHOD_EXPORT(SetAggressiveness),
    PY_METHOD_EXPORT(RunHunts),
    PY_METHOD_EXPORT(Monitor),
    PY_METHOD_EXPORT(SetReactions),
    PY_METHOD_EXPORT(AddMitigations),
    PY_METHOD_EXPORT(RunMitigations),
    PY_METHOD_EXPORT(RunMitigationsWithConfig),
    PY_METHOD_EXPORT(WaitForTasks),
    PY_METHOD_EXPORT(GetAllDetections),
    PY_METHOD_EXPORT(RetrieveMessages),
    PY_METHOD_EXPORT(ScanProcess),
    PY_METHOD_EXPORT(ScanFile),
    PY_METHOD_EXPORT(ScanFolder),

    { NULL, NULL, 0, NULL },
};
PyModuleDef bsModule = { PyModuleDef_HEAD_INIT, "bluespawn", "Bluespawn python bindings", -1, methods };

PyMODINIT_FUNC PyInit_bluespawn() {
    if(!bluespawnLibrary) {
        bluespawnLibrary = LoadLibraryW(L"BLUESPAWN-client-lib.dll");
        if(!bluespawnLibrary) {
            return NULL;
        }

        ((void (*)()) GetProcAddress(bluespawnLibrary, "Initialize"))();
    }
    return PyModule_Create(&bsModule);
}
