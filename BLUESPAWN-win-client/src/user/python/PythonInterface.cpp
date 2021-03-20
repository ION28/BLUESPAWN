#define PY_SSIZE_T_CLEAN
#include "util/StringUtils.h"

#include "python3.9/Python.h"
#include "user/PyIO.h"
#include "user/bluespawn.h"

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

const IOBase& Bluespawn::io = PyIO::GetInstance();
Bluespawn bs{};

PyObject* bluespawnError;

PyObject* SerializeDetection(const std::shared_ptr<Detection>& detection) {
    if(!detection){
        Py_RETURN_NONE;
    }
    BeginCriticalSection _{ detection->hGuard };
    auto dataDict{ PyDict_New() };
    for(auto& line : detection->Serialize()) {
        PyDict_SetItem(dataDict, PyUnicode_FromWideChar(line.first.c_str(), line.first.length()),
                       PyUnicode_FromWideChar(line.second.c_str(), line.second.length()));
    }
    auto detectionDict{ PyDict_New() };
    PyDict_SetItem(detectionDict, PyUnicode_FromString("ID"), PyLong_FromLong(detection->dwID));

    auto time{ FormatWindowsTime(detection->context.DetectionCreatedTime) };
    PyDict_SetItem(detectionDict, PyUnicode_FromString("time"), PyUnicode_FromWideChar(time.c_str(), time.length()));
    PyDict_SetItem(detectionDict, PyUnicode_FromString("certainty"),
                   PyFloat_FromDouble(detection->info.GetCertainty()));
    PyDict_SetItem(detectionDict, PyUnicode_FromString("raw-certainty"),
                   PyFloat_FromDouble(detection->info.GetIntrinsicCertainty()));
    if(detection->context.FirstEvidenceTime) {
        auto ftime{ FormatWindowsTime(*detection->context.FirstEvidenceTime) };
        PyDict_SetItem(detectionDict, PyUnicode_FromString("first-evidence-time"),
                       PyUnicode_FromWideChar(ftime.c_str(), ftime.length()));
    }
    if(detection->context.note) {
        PyDict_SetItem(detectionDict, PyUnicode_FromString("note"),
                       PyUnicode_FromWideChar(detection->context.note->c_str(), detection->context.note->length()));
    }
    if(detection->context.hunts.size()) {
        auto* list{ PyList_New(detection->context.hunts.size()) };
        int index{ 0 };
        for(auto& hunt : detection->context.hunts) {
            PyList_SetItem(list, index++, PyUnicode_FromWideChar(hunt.c_str(), hunt.length()));
        }
        PyDict_SetItem(detectionDict, PyUnicode_FromString("associated-hunts"), list);
    }
    PyDict_SetItem(detectionDict, PyUnicode_FromString("associated-data"), dataDict);

    auto associations{ detection->info.GetAssociations() };
    if(associations.size()) {
        auto* list{ PyList_New(associations.size()) };
        int index{ 0 };
        for(auto& assoc : associations) {
            auto* tuple{ PyTuple_New(2) };
            PyTuple_SetItem(tuple, 0, PyLong_FromLong(assoc.first->dwID));
            PyTuple_SetItem(tuple, 0, PyFloat_FromDouble(assoc.second));
            PyList_SetItem(list, index++, tuple);
        }
        PyDict_SetItem(detectionDict, PyUnicode_FromString("associated-detections"), list);
    }

    return detectionDict;
}

PyObject* ConvertMitigationReports(const std::map<Mitigation*, MitigationReport>& reports) {
    auto mitigationDict{ PyDict_New() };
    for(auto& report : reports) {
        auto dict{ PyDict_New() };
        for(auto& policy : report.second.results) {
            PyDict_SetItem(dict,
                           PyUnicode_FromWideChar(policy.first->GetPolicyName().c_str(),
                                                  policy.first->GetPolicyName().length()),
                           PyLong_FromLong(static_cast<long>(policy.second)));
        }
        PyDict_SetItem(mitigationDict,
                       PyUnicode_FromWideChar(report.first->GetName().c_str(), report.first->GetName().length()), dict);
    }
    return mitigationDict;
}

std::vector<std::wstring> ReadStringArray(PyObject* arr) {
    if(!PyList_Check(arr)) {
        return {};
    } else {
        std::vector<std::wstring> strs{};
        for(int i = 0; i < PyList_Size(arr); i++) {
            auto elem{ PyList_GetItem(arr, i) };
            Py_ssize_t size;
            auto str{ PyUnicode_AsWideCharString(elem, &size) };
            if(str) {
                strs.emplace_back(std::wstring{ str, static_cast<size_t>(size) });
                PyMem_Free(str);
            } else {
                throw std::exception("List did not contain strings");
            }
        }
        return strs;
    }
}

PyObject* AddDetectionSink(PyObject* self, PyObject* args, PyObject* keywds) {
    PyErr_SetString(PyExc_NotImplementedError, "AddDetectionSink is not implemented in BLUESPAWN-agent7 v0.1");
    return nullptr;
}

PyObject* SetLogSinks(PyObject* self, PyObject* args, PyObject* keywds) {
    PyObject* sinks{ nullptr };
    const char* outDirectory{ nullptr };
    static char* kwlist[] = { "sinks", "outdir", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "|Os", kwlist, &sinks, &outDirectory)) {
        if(sinks && !PyList_Check(sinks)) {
            PyErr_SetString(PyExc_TypeError, "sinks must be a list");
            return nullptr;
        } else {
            try {
                auto list = sinks ? ReadStringArray(sinks) : std::vector<std::wstring>{ L"console" };
                bs.SetLogSinks(list, outDirectory ? StringToWidestring(outDirectory) : L".");
                Py_RETURN_NONE;
            } catch(std::exception e) {
                PyErr_SetString(PyExc_TypeError, "List elements must be strings");
                return nullptr;
            }
        }
    } else {
        return nullptr;
    }
}

PyObject* SetAggressiveness(PyObject* self, PyObject* args, PyObject* keywds) {
    Aggressiveness level;
    static char* kwlist[] = { "aggressiveness", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &level)) {
        bs.SetAggressiveness(level);
        Py_RETURN_NONE;
    } else {
        return nullptr;
    }
}

PyObject* RunHunts(PyObject* self, PyObject* args, PyObject* keywds) {
    PyObject* hunts{ nullptr };
    PyObject* excludes{ nullptr };
    static char* kwlist[] = { "include", "exclude", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "|OO", kwlist, &hunts, &excludes)) {
        if((hunts && !PyList_Check(hunts)) || (excludes && !PyList_Check(excludes))) {
            PyErr_SetString(PyExc_TypeError, "Arguments must be lists");
            return nullptr;
        } else {
            try {
                auto include = hunts ? ReadStringArray(hunts) : std::vector<std::wstring>{};
                auto exclude = excludes ? ReadStringArray(excludes) : std::vector<std::wstring>{};
                bs.RunHunts(include, exclude);
                Py_RETURN_NONE;
            } catch(std::exception e) {
                PyErr_SetString(PyExc_TypeError, "List elements must be strings");
                return nullptr;
            }
        }
    } else {
        return nullptr;
    }
}

PyObject* Monitor(PyObject* self, PyObject* args, PyObject* keywds) {
    PyObject* hunts{ nullptr };
    PyObject* excludes{ nullptr };
    static char* kwlist[] = { "hunts", "exclude", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "|OO", kwlist, &hunts, &excludes)) {
        if((hunts && !PyList_Check(hunts)) || (excludes && !PyList_Check(excludes))) {
            PyErr_SetString(PyExc_TypeError, "Arguments must be lists");
            return nullptr;
        } else {
            try {
                auto include = hunts ? ReadStringArray(hunts) : std::vector<std::wstring>{};
                auto exclude = excludes ? ReadStringArray(excludes) : std::vector<std::wstring>{};
                bs.Monitor(include, exclude);
                Py_RETURN_NONE;
            } catch(std::exception e) {
                PyErr_SetString(PyExc_TypeError, "List elements must be strings");
                return nullptr;
            }
        }
    } else {
        return nullptr;
    }
}

PyObject* SetReactions(PyObject* self, PyObject* args, PyObject* keywds) {
    PyObject* reactions{ nullptr };
    static char* kwlist[] = { "reactions", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "O", kwlist, &reactions)) {
        if(reactions && !PyList_Check(reactions)) {
            PyErr_SetString(PyExc_TypeError, "reactions must be a list");
            return nullptr;
        } else {
            try {
                bs.SetReactions(ReadStringArray(reactions));
                Py_RETURN_NONE;
            } catch(std::exception e) {
                PyErr_SetString(PyExc_TypeError, "List elements must be strings");
                return nullptr;
            }
        }
    } else {
        return nullptr;
    }
}

PyObject* AddMitigations(PyObject* self, PyObject* args, PyObject* keywds) {
    char* mitigations{ nullptr };
    static char* kwlist[] = { "mitigations", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &mitigations)) {
        bs.AddMitigations(mitigations);
        Py_RETURN_NONE;
    } else {
        return nullptr;
    }
}

PyObject* RunMitigations(PyObject* self, PyObject* args, PyObject* keywds) {
    EnforcementLevel level = EnforcementLevel::Moderate;
    bool enforce = true;
    static char* kwlist[] = { "level", "enforce", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "|fp", kwlist, &level, &enforce)) {
        auto res{ bs.RunMitigations(level, enforce) };
        return ConvertMitigationReports(res);
    } else {
        return nullptr;
    }
}

PyObject* RunMitigationsWithConfig(PyObject* self, PyObject* args, PyObject* keywds) {
    char* config;
    bool enforce;
    static char* kwlist[] = { "config", "enforce", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "|sp", kwlist, &config, &enforce)) {
        try {
            auto res{ bs.RunMitigations(json::parse(nlohmann::detail::span_input_adapter(config, strlen(config))),
                                        enforce) };
            return ConvertMitigationReports(res);
        } catch(std::exception& e) {
            PyErr_SetString(PyExc_ValueError, e.what());
            return nullptr;
        }
        Py_RETURN_NONE;
    } else {
        return nullptr;
    }
}

PyObject* WaitForTasks(PyObject* self, PyObject* args, PyObject* keywds) {
    bs.WaitForTasks();
    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    SetEvent(hRecordEvent);
    Py_RETURN_NONE;
}

PyObject* GetAllDetections(PyObject* self, PyObject* args, PyObject* keywds) {
    auto detections{ bs.detections.GetAllDetections() };
    auto* list{ PyList_New(detections.size()) };
    int index{ 0 };
    for(auto& detection : detections) {
        PyList_SetItem(list, index++, SerializeDetection(detection));
    }
    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    SetEvent(hRecordEvent);
    return list;
}

PyObject* RetrieveMessages(PyObject* self, PyObject* args, PyObject* keywds) {
    auto* list{ PyList_New(pyMessageBuffer.size()) };
    int index{ 0 };
    for(auto& message : pyMessageBuffer) {
        PyList_SetItem(list, index++, PyUnicode_FromWideChar(message.c_str(), message.size()));
    }
    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    SetEvent(hRecordEvent);
    return list;
}

PyObject* ScanProcess(PyObject* self, PyObject* args, PyObject* keywds) {
    DWORD dwPID;
    static char* kwlist[] = { "pid", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &dwPID)) {
        return SerializeDetection(bs.ScanProcess(dwPID));
    } else {
        return nullptr;
    }
}

PyObject* ScanFile(PyObject* self, PyObject* args, PyObject* keywds) {
    const char* filepath;
    static char* kwlist[] = { "file_path", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &filepath)) {
        return SerializeDetection(bs.ScanFile(StringToWidestring(filepath)));
    } else {
        return nullptr;
    }
}

PyObject* ScanFolder(PyObject* self, PyObject* args, PyObject* keywds) {
    const char* folderPath;
    static char* kwlist[] = { "folder_path", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &folderPath)) {
        auto detections{ bs.ScanFolder(StringToWidestring(folderPath)) };
        auto* list{ PyList_New(detections.size()) };
        int index{ 0 };
        for(auto& detection : detections) {
            if(detection){
                PyList_SetItem(list, index++, SerializeDetection(detection));
            }
        }
        return list;
    } else {
        return nullptr;
    }
}

#define PY_METHOD_EXPORT(name) \
    { #name, (PyCFunction) name, METH_VARARGS | METH_KEYWORDS, name##_doc }

PyMethodDef methods[]{
    PY_METHOD_EXPORT(AddDetectionSink), PY_METHOD_EXPORT(SetLogSinks),      PY_METHOD_EXPORT(SetAggressiveness),
    PY_METHOD_EXPORT(RunHunts),         PY_METHOD_EXPORT(Monitor),          PY_METHOD_EXPORT(SetReactions),
    PY_METHOD_EXPORT(AddMitigations),   PY_METHOD_EXPORT(RunMitigations),   PY_METHOD_EXPORT(RunMitigationsWithConfig),
    PY_METHOD_EXPORT(WaitForTasks),     PY_METHOD_EXPORT(GetAllDetections), PY_METHOD_EXPORT(RetrieveMessages),
    PY_METHOD_EXPORT(ScanProcess),      PY_METHOD_EXPORT(ScanFile),         PY_METHOD_EXPORT(ScanFolder),

    { nullptr, nullptr, 0, nullptr },
};

PyModuleDef bsModule{ PyModuleDef_HEAD_INIT, "bluespawn", nullptr, -1, methods };

PyMODINIT_FUNC PyInit_bluespawn() {
    PyObject* m;

    m = PyModule_Create(&bsModule);
    if(m == NULL)
        return NULL;

    bluespawnError = PyErr_NewException("bluespawn.error", NULL, NULL);
    Py_XINCREF(bluespawnError);
    if(PyModule_AddObject(m, "error", bluespawnError) < 0) {
        Py_XDECREF(bluespawnError);
        Py_CLEAR(bluespawnError);
        Py_DECREF(m);
        return nullptr;
    }

    return m;
}
