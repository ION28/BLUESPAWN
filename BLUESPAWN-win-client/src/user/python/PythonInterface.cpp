#define PY_SSIZE_T_CLEAN
#define Py_BUILD_CORE_MODULE
#include "util/StringUtils.h"

#include "python3.9/Python.h"
#include "user/PyIO.h"
#include "user/bluespawn.h"

#define PY_FUNC(name) decltype(&name) __##name{};

#define LINK_PY_FUNC(name) __##name = (decltype(&name)) name##_;

#define REQ_PY_FUNC(name) LPVOID name##_

const IOBase& Bluespawn::io = PyIO::GetInstance();
Bluespawn bs{};

#ifdef Py_LIMITED_API
#define PyType_HasFeature(t,f)  ((PyType_GetFlags(t) & (f)) != 0)
#else
#define PyType_HasFeature(t,f)  (((t)->tp_flags & (f)) != 0)
#endif

PY_FUNC(PyArg_ParseTupleAndKeywords);
PY_FUNC(PyDict_New);
PY_FUNC(PyDict_SetItem);
PY_FUNC(PyErr_SetString);
PY_FUNC(PyFloat_FromDouble);
PY_FUNC(PyList_GetItem);
PY_FUNC(PyList_New);
PY_FUNC(PyList_SetItem);
PY_FUNC(PyList_Size);
PY_FUNC(PyLong_FromLong);
PY_FUNC(PyMem_Free);
PY_FUNC(PyTuple_New);
PY_FUNC(PyTuple_SetItem);
PY_FUNC(PyUnicode_AsWideCharString);
PY_FUNC(PyUnicode_FromString);
PY_FUNC(PyUnicode_FromWideChar);

#define __PyList_Check(obj) PyType_HasFeature(obj->ob_type, 1UL << 25)

PyObject* SerializeDetection(const std::shared_ptr<Detection>& detection) {
    if(!detection) {
        Py_RETURN_NONE;
    }
    BeginCriticalSection _{ detection->hGuard };
    auto dataDict{ __PyDict_New() };
    for(auto& line : detection->Serialize()) {
        __PyDict_SetItem(dataDict, __PyUnicode_FromWideChar(line.first.c_str(), line.first.length()),
                         __PyUnicode_FromWideChar(line.second.c_str(), line.second.length()));
    }
    auto detectionDict{ __PyDict_New() };
    __PyDict_SetItem(detectionDict, __PyUnicode_FromString("ID"), __PyLong_FromLong(detection->dwID));

    auto time{ FormatWindowsTime(detection->context.DetectionCreatedTime) };
    __PyDict_SetItem(detectionDict, __PyUnicode_FromString("time"),
                     __PyUnicode_FromWideChar(time.c_str(), time.length()));
    __PyDict_SetItem(detectionDict, __PyUnicode_FromString("certainty"),
                     __PyFloat_FromDouble(detection->info.GetCertainty()));
    __PyDict_SetItem(detectionDict, __PyUnicode_FromString("raw-certainty"),
                     __PyFloat_FromDouble(detection->info.GetIntrinsicCertainty()));
    if(detection->context.FirstEvidenceTime) {
        auto ftime{ FormatWindowsTime(*detection->context.FirstEvidenceTime) };
        __PyDict_SetItem(detectionDict, __PyUnicode_FromString("first-evidence-time"),
                         __PyUnicode_FromWideChar(ftime.c_str(), ftime.length()));
    }
    if(detection->context.note) {
        __PyDict_SetItem(detectionDict, __PyUnicode_FromString("note"),
                         __PyUnicode_FromWideChar(detection->context.note->c_str(), detection->context.note->length()));
    }
    if(detection->context.hunts.size()) {
        auto* list{ __PyList_New(detection->context.hunts.size()) };
        int index{ 0 };
        for(auto& hunt : detection->context.hunts) {
            __PyList_SetItem(list, index++, __PyUnicode_FromWideChar(hunt.c_str(), hunt.length()));
        }
        __PyDict_SetItem(detectionDict, __PyUnicode_FromString("associated-hunts"), list);
    }
    __PyDict_SetItem(detectionDict, __PyUnicode_FromString("associated-data"), dataDict);

    auto associations{ detection->info.GetAssociations() };
    if(associations.size()) {
        auto* list{ __PyList_New(associations.size()) };
        int index{ 0 };
        for(auto& assoc : associations) {
            auto* tuple{ __PyTuple_New(2) };
            __PyTuple_SetItem(tuple, 0, __PyLong_FromLong(assoc.first->dwID));
            __PyTuple_SetItem(tuple, 1, __PyFloat_FromDouble(assoc.second));
            __PyList_SetItem(list, index++, tuple);
        }
        __PyDict_SetItem(detectionDict, __PyUnicode_FromString("associated-detections"), list);
    }

    return detectionDict;
}

PyObject* ConvertMitigationReports(const std::map<Mitigation*, MitigationReport>& reports) {
    auto mitigationDict{ __PyDict_New() };
    for(auto& report : reports) {
        auto dict{ __PyDict_New() };
        for(auto& policy : report.second.results) {
            __PyDict_SetItem(dict,
                             __PyUnicode_FromWideChar(policy.first->GetPolicyName().c_str(),
                                                      policy.first->GetPolicyName().length()),
                             __PyLong_FromLong(static_cast<long>(policy.second)));
        }
        __PyDict_SetItem(mitigationDict,
                         __PyUnicode_FromWideChar(report.first->GetName().c_str(), report.first->GetName().length()),
                         dict);
    }
    return mitigationDict;
}

std::vector<std::wstring> ReadStringArray(PyObject* arr) {
    if(!__PyList_Check(arr)) {
        return {};
    } else {
        std::vector<std::wstring> strs{};
        for(int i = 0; i < __PyList_Size(arr); i++) {
            auto elem{ __PyList_GetItem(arr, i) };
            Py_ssize_t size;
            auto str{ __PyUnicode_AsWideCharString(elem, &size) };
            if(str) {
                strs.emplace_back(std::wstring{ str, static_cast<size_t>(size) });
                __PyMem_Free(str);
            } else {
                throw std::exception("List did not contain strings");
            }
        }
        return strs;
    }
}

extern "C" __declspec(dllexport) void Initialize(REQ_PY_FUNC(PyArg_ParseTupleAndKeywords),
                                                 REQ_PY_FUNC(PyDict_New),
                                                 REQ_PY_FUNC(PyDict_SetItem),
                                                 REQ_PY_FUNC(PyErr_SetString),
                                                 REQ_PY_FUNC(PyFloat_FromDouble),
                                                 REQ_PY_FUNC(PyList_GetItem),
                                                 REQ_PY_FUNC(PyList_New),
                                                 REQ_PY_FUNC(PyList_SetItem),
                                                 REQ_PY_FUNC(PyList_Size),
                                                 REQ_PY_FUNC(PyLong_FromLong),
                                                 REQ_PY_FUNC(PyMem_Free),
                                                 REQ_PY_FUNC(PyTuple_New),
                                                 REQ_PY_FUNC(PyTuple_SetItem),
                                                 REQ_PY_FUNC(PyUnicode_AsWideCharString),
                                                 REQ_PY_FUNC(PyUnicode_FromString),
                                                 REQ_PY_FUNC(PyUnicode_FromWideChar)) {
    LINK_PY_FUNC(PyArg_ParseTupleAndKeywords);
    LINK_PY_FUNC(PyDict_New);
    LINK_PY_FUNC(PyDict_SetItem);
    LINK_PY_FUNC(PyErr_SetString);
    LINK_PY_FUNC(PyFloat_FromDouble);
    LINK_PY_FUNC(PyList_GetItem);
    LINK_PY_FUNC(PyList_New);
    LINK_PY_FUNC(PyList_SetItem);
    LINK_PY_FUNC(PyList_Size);
    LINK_PY_FUNC(PyLong_FromLong);
    LINK_PY_FUNC(PyMem_Free);
    LINK_PY_FUNC(PyTuple_New);
    LINK_PY_FUNC(PyTuple_SetItem);
    LINK_PY_FUNC(PyUnicode_AsWideCharString);
    LINK_PY_FUNC(PyUnicode_FromString);
    LINK_PY_FUNC(PyUnicode_FromWideChar);

    Bluespawn::mitigationRecord.Initialize();
}

extern "C" __declspec(dllexport) PyObject* AddDetectionSink(PyObject* self, PyObject* args, PyObject* keywds) {
    __PyErr_SetString(PyExc_NotImplementedError, "AddDetectionSink is not implemented in BLUESPAWN-agent7 v0.1");
    return nullptr;
}

extern "C" __declspec(dllexport) PyObject* SetLogSinks(PyObject* self, PyObject* args, PyObject* keywds) {
    PyObject* sinks{ nullptr };
    const char* outDirectory{ nullptr };
    static char* kwlist[] = { "sinks", "outdir", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "|Os", kwlist, &sinks, &outDirectory)) {
        if(sinks && !__PyList_Check(sinks)) {
            __PyErr_SetString(PyExc_TypeError, "sinks must be a list");
            return nullptr;
        } else {
            try {
                auto list = sinks ? ReadStringArray(sinks) : std::vector<std::wstring>{ L"console" };
                bs.SetLogSinks(list, outDirectory ? StringToWidestring(outDirectory) : L".");
                Py_RETURN_NONE;
            } catch(std::exception e) {
                __PyErr_SetString(PyExc_TypeError, "List elements must be strings");
                return nullptr;
            }
        }
    } else {
        return nullptr;
    }
}

extern "C" __declspec(dllexport) PyObject* SetAggressiveness(PyObject* self, PyObject* args, PyObject* keywds) {
    Aggressiveness level;
    static char* kwlist[] = { "aggressiveness", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &level)) {
        bs.SetAggressiveness(level);
        Py_RETURN_NONE;
    } else {
        return nullptr;
    }
}

extern "C" __declspec(dllexport) PyObject* RunHunts(PyObject* self, PyObject* args, PyObject* keywds) {
    PyObject* hunts{ nullptr };
    PyObject* excludes{ nullptr };
    static char* kwlist[] = { "include", "exclude", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "|OO", kwlist, &hunts, &excludes)) {
        if((hunts && !__PyList_Check(hunts)) || (excludes && !__PyList_Check(excludes))) {
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

extern "C" __declspec(dllexport) PyObject* Monitor(PyObject* self, PyObject* args, PyObject* keywds) {
    PyObject* hunts{ nullptr };
    PyObject* excludes{ nullptr };
    static char* kwlist[] = { "hunts", "exclude", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "|OO", kwlist, &hunts, &excludes)) {
        if((hunts && !__PyList_Check(hunts)) || (excludes && !__PyList_Check(excludes))) {
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

extern "C" __declspec(dllexport) PyObject* SetReactions(PyObject* self, PyObject* args, PyObject* keywds) {
    PyObject* reactions{ nullptr };
    static char* kwlist[] = { "reactions", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "O", kwlist, &reactions)) {
        if(reactions && !__PyList_Check(reactions)) {
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

extern "C" __declspec(dllexport) PyObject* AddMitigations(PyObject* self, PyObject* args, PyObject* keywds) {
    char* mitigations{ nullptr };
    static char* kwlist[] = { "mitigations", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &mitigations)) {
        bs.AddMitigations(mitigations);
        Py_RETURN_NONE;
    } else {
        return nullptr;
    }
}

extern "C" __declspec(dllexport) PyObject* RunMitigations(PyObject* self, PyObject* args, PyObject* keywds) {
    EnforcementLevel level = EnforcementLevel::Moderate;
    bool enforce = true;
    static char* kwlist[] = { "level", "enforce", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "|fp", kwlist, &level, &enforce)) {
        auto res{ bs.RunMitigations(level, enforce) };
        return ConvertMitigationReports(res);
    } else {
        return nullptr;
    }
}

extern "C" __declspec(dllexport) PyObject* RunMitigationsWithConfig(PyObject* self, PyObject* args, PyObject* keywds) {
    char* config;
    bool enforce;
    static char* kwlist[] = { "config", "enforce", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "|sp", kwlist, &config, &enforce)) {
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

extern "C" __declspec(dllexport) PyObject* WaitForTasks(PyObject* self, PyObject* args, PyObject* keywds) {
    bs.WaitForTasks();
    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    SetEvent(hRecordEvent);
    bs.WaitForTasks();
    Py_RETURN_NONE;
}

extern "C" __declspec(dllexport) PyObject* GetAllDetections(PyObject* self, PyObject* args, PyObject* keywds) {
    auto detections{ bs.detections.GetAllDetections() };
    auto* list{ __PyList_New(detections.size()) };
    int index{ 0 };
    for(auto& detection : detections) {
        __PyList_SetItem(list, index++, SerializeDetection(detection));
    }
    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    SetEvent(hRecordEvent);
    return list;
}

extern "C" __declspec(dllexport) PyObject* RetrieveMessages(PyObject* self, PyObject* args, PyObject* keywds) {
    auto* list{ __PyList_New(pyMessageBuffer.size()) };
    int index{ 0 };
    for(auto& message : pyMessageBuffer) {
        __PyList_SetItem(list, index++, PyUnicode_FromWideChar(message.c_str(), message.size()));
    }
    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    SetEvent(hRecordEvent);
    return list;
}

extern "C" __declspec(dllexport) PyObject* ScanProcess(PyObject* self, PyObject* args, PyObject* keywds) {
    DWORD dwPID;
    static char* kwlist[] = { "pid", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &dwPID)) {
        return SerializeDetection(bs.ScanProcess(dwPID));
    } else {
        return nullptr;
    }
}

extern "C" __declspec(dllexport) PyObject* ScanFile(PyObject* self, PyObject* args, PyObject* keywds) {
    const char* filepath;
    static char* kwlist[] = { "file_path", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &filepath)) {
        return SerializeDetection(bs.ScanFile(StringToWidestring(filepath)));
    } else {
        return nullptr;
    }
}

extern "C" __declspec(dllexport) PyObject* ScanFolder(PyObject* self, PyObject* args, PyObject* keywds) {
    const char* folderPath;
    static char* kwlist[] = { "folder_path", NULL };
    if(__PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &folderPath)) {
        auto detections{ bs.ScanFolder(StringToWidestring(folderPath)) };
        auto* list{ __PyList_New(detections.size()) };
        int index{ 0 };
        for(auto& detection : detections) {
            if(detection) {
                __PyList_SetItem(list, index++, SerializeDetection(detection));
            }
        }
        return list;
    } else {
        return nullptr;
    }
}
