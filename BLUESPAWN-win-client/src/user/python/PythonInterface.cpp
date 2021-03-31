#define PY_SSIZE_T_CLEAN
#define Py_BUILD_CORE_MODULE
#include "util/StringUtils.h"

#include "Python.h"
#include "nlohmann/json.hpp"
#include "user/PyIO.h"
#include "user/bluespawn.h"

const IOBase& Bluespawn::io = PyIO::GetInstance();
Bluespawn bs{};

PyObject* SerializeDetection(const std::shared_ptr<Detection>& detection) {
    if(!detection) {
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
    PyDict_SetItem(detectionDict, PyUnicode_FromString("time"),
                     PyUnicode_FromWideChar(time.c_str(), time.length()));
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
            PyTuple_SetItem(tuple, 1, PyFloat_FromDouble(assoc.second));
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
                         PyUnicode_FromWideChar(report.first->GetName().c_str(), report.first->GetName().length()),
                         dict);
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

extern "C" __declspec(dllexport) void Initialize() {
    Bluespawn::mitigationRecord.Initialize();
}

extern "C" __declspec(dllexport) PyObject* AddDetectionSink(PyObject* self, PyObject* args, PyObject* keywds) {
    PyErr_SetString(PyExc_NotImplementedError, "AddDetectionSink is not implemented in BLUESPAWN-agent7 v0.1");
    return nullptr;
}

extern "C" __declspec(dllexport) PyObject* SetLogSinks(PyObject* self, PyObject* args, PyObject* keywds) {
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

extern "C" __declspec(dllexport) PyObject* SetAggressiveness(PyObject* self, PyObject* args, PyObject* keywds) {
    Aggressiveness level;
    static char* kwlist[] = { "aggressiveness", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &level)) {
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

extern "C" __declspec(dllexport) PyObject* Monitor(PyObject* self, PyObject* args, PyObject* keywds) {
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

extern "C" __declspec(dllexport) PyObject* SetReactions(PyObject* self, PyObject* args, PyObject* keywds) {
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

extern "C" __declspec(dllexport) PyObject* AddMitigations(PyObject* self, PyObject* args, PyObject* keywds) {
    char* mitigations{ nullptr };
    static char* kwlist[] = { "mitigations", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &mitigations)) {
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
    if(PyArg_ParseTupleAndKeywords(args, keywds, "|fp", kwlist, &level, &enforce)) {
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

extern "C" __declspec(dllexport) PyObject* WaitForTasks(PyObject* self, PyObject* args, PyObject* keywds) {
    bs.WaitForTasks();
    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    SetEvent(hRecordEvent);
    bs.WaitForTasks();
    Py_RETURN_NONE;
}

extern "C" __declspec(dllexport) PyObject* GetAllDetections(PyObject* self, PyObject* args, PyObject* keywds) {
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

extern "C" __declspec(dllexport) PyObject* RetrieveMessages(PyObject* self, PyObject* args, PyObject* keywds) {
    auto* list{ PyList_New(pyMessageBuffer.size()) };
    int index{ 0 };
    for(auto& message : pyMessageBuffer) {
        PyList_SetItem(list, index++, PyUnicode_FromWideChar(message.c_str(), message.size()));
    }
    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    SetEvent(hRecordEvent);
    return list;
}

extern "C" __declspec(dllexport) PyObject* ScanProcess(PyObject* self, PyObject* args, PyObject* keywds) {
    DWORD dwPID;
    static char* kwlist[] = { "pid", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &dwPID)) {
        return SerializeDetection(bs.ScanProcess(dwPID));
    } else {
        return nullptr;
    }
}

extern "C" __declspec(dllexport) PyObject* ScanFile(PyObject* self, PyObject* args, PyObject* keywds) {
    const char* filepath;
    static char* kwlist[] = { "file_path", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &filepath)) {
        return SerializeDetection(bs.ScanFile(StringToWidestring(filepath)));
    } else {
        return nullptr;
    }
}

extern "C" __declspec(dllexport) PyObject* ScanFolder(PyObject* self, PyObject* args, PyObject* keywds) {
    const char* folderPath;
    static char* kwlist[] = { "folder_path", NULL };
    if(PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &folderPath)) {
        auto detections{ bs.ScanFolder(StringToWidestring(folderPath)) };
        auto* list{ PyList_New(detections.size()) };
        int index{ 0 };
        for(auto& detection : detections) {
            if(detection) {
                PyList_SetItem(list, index++, SerializeDetection(detection));
            }
        }
        return list;
    } else {
        return nullptr;
    }
}
