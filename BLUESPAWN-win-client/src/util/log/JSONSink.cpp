#include "util/log/JSONSink.h"

#include <chrono>
#include <fstream>
#include <iostream>

#include "util/StringUtils.h"
#include "util/Utils.h"

#include "user/bluespawn.h"

namespace Log {

    std::wstring JSONSink::ToWstringPad(DWORD value, size_t length = 2) {
        wchar_t* buf = new wchar_t[length + 1];
        swprintf(buf, (L"%0" + std::to_wstring(length) + L"d").c_str(), value);
        std::wstring str = buf;
        delete[] buf;
        return str;
    }

    void UpdateLog(JSONSink* sink) {
        HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
        while(true) {
            WaitForSingleObject(hRecordEvent, INFINITE);
            sink->Flush();
        }
    }

    JSONSink::JSONSink() :
        thread{ CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, CREATE_SUSPENDED, nullptr) } {
        JSONDoc = json::object();
        JSONDoc["bluespawn"] = json::object();
        JSONDoc["bluespawn"]["log-messages"] = json::array();

        SYSTEMTIME time{};
        GetLocalTime(&time);
        wFileName = L"bluespawn-" + ToWstringPad(time.wMonth) + L"-" + ToWstringPad(time.wDay) + L"-" +
                    ToWstringPad(time.wYear, 4) + L"-" + ToWstringPad(time.wHour) + ToWstringPad(time.wMinute) + L"-" +
                    ToWstringPad(time.wSecond) + L".json";
        ResumeThread(thread);
    }   // namespace Log

    JSONSink::JSONSink(const std::wstring& wFileName) :
        wFileName{ wFileName }, thread{ CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, 0, nullptr) } {
        JSONDoc = json::object();
        JSONDoc["bluespawn"] = json::object();
        JSONDoc["bluespawn"]["log-messages"] = json::array();
    }

    JSONSink::~JSONSink() {
        std::ofstream out(WidestringToString(wFileName));
        out << std::setw(4) << JSONDoc << std::endl;
        TerminateThread(thread, 0);
    }

    void InsertElement(IN json JSONDoc, IN json parent, IN CONST std::string& name, IN CONST std::wstring& value) {
        parent[name] = WidestringToString(value).c_str();
    }

    void JSONSink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection) {
        BeginCriticalSection __{ *detection };
        BeginCriticalSection _{ hGuard };
        /*
        if(detections.find(detection->dwID) != detections.end()) {
            for(auto child{ detections.at(detection->dwID)->FirstChildElement() }; child;
                child = child->NextSiblingElement()) {
                if(child->Name() == std::string{ "certainty" }) {
                    child->SetText(detection->info.GetCertainty());
                }
                if(child->Name() == std::string{ "raw-certainty" }) {
                    child->SetText(detection->info.GetIntrinsicCertainty());
                }
            }
        }
        */
    }

    void AddAssociation() {
        /*
        for(auto child{ to->FirstChildElement() }; child; child = child->NextSiblingElement()) {
            if(child->Name() == std::string{ "associated-detections" }) {
                for(auto elem{ child->FirstChildElement() }; elem; elem = elem->NextSiblingElement()) {
                    if(elem->GetText() == std::to_string(id)) {
                        double existing{ 0 };
                        elem->FindAttribute("strength")->QueryDoubleValue(&existing);
                        elem->SetAttribute("strength", 1.0 - (1 - existing) * (1 - strength));
                        return;
                    }
                }

                auto elem{ doc.NewElement("association") };
                elem->SetAttribute("strength", strength);
                elem->SetText(std::to_string(id).c_str());
                child->InsertEndChild(elem);
                return;
            }
        }

        auto assocations{ doc.NewElement("associated-detections") };
        auto elem{ doc.NewElement("association") };
        elem->SetAttribute("strength", strength);
        elem->SetText(std::to_string(id).c_str());
        assocations->InsertEndChild(elem);
        to->InsertEndChild(assocations);
        */
    }

    void JSONSink::RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type) {
        if(type == RecordType::PreScan && !Bluespawn::EnablePreScanDetections) {
            return;
        }

        BeginCriticalSection __{ *detection };
        BeginCriticalSection _{ hGuard };

        if(JSONDoc["bluespawn"]["detections"] == nullptr) {
            JSONDoc["bluespawn"]["detections"] = json::array();
        }

        if(detections.find(detection->dwID) != detections.end()) {
            //TODO: Delete current detection within json
        }

        json detect = {};

        if(type == RecordType::PreScan) {
            detect["prescan"] = "true";
        }

        detect["type"] = (detection->type == DetectionType::FileDetection ?
                              "File" :
                              detection->type == DetectionType::ProcessDetection ?
                              "Process" :
                              detection->type == DetectionType::RegistryDetection ?
                              "Registry" :
                              detection->type == DetectionType::ServiceDetection ?
                              "Service" :
                              WidestringToString(std::get<OtherDetectionData>(detection->data).DetectionType));

        detect["id"] = std::to_string(detection->dwID);
        detect["time"] = WidestringToString(FormatWindowsTime(detection->context.DetectionCreatedTime));

        if(detection->context.FirstEvidenceTime) {
            detect["first-evidence-time"] = FormatWindowsTime(*detection->context.FirstEvidenceTime);
        }

        if(detection->context.note) {
            detect["note"] = WidestringToString(*detection->context.note);
        }

        detect["certainty"] = std::to_string(detection->info.GetCertainty());
        detect["raw-certainty"] = std::to_string(detection->info.GetIntrinsicCertainty());

        if(detection->context.hunts.size()) {
            detect["associated-hunts"] = json::array();
            for(const auto& hunt : detection->context.hunts) {
                detect["associated-hunts"].push_back(WidestringToString(hunt));
            }
        }

        detect["associated-data"] = json::object();
        for(const auto& entry : detection->Serialize()) {
            detect["associated-data"][WidestringToString(entry.first)] = WidestringToString(entry.second);
        }

        auto assoc{ detection->info.GetAssociations() };
        if(assoc.size()) {
            detect["associated-detections"] = json::array();
            for(const auto& det : assoc) {
                detect["associated-detections"].push_back(
                    { { "strength", static_cast<double>(det.second) }, { "id", std::to_string(det.first->dwID) } });
            }
        }

        JSONDoc["bluespawn"]["detections"].push_back(detect);
    }

    void JSONSink::RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                     IN CONST std::shared_ptr<Detection>& second,
                                     IN CONST Association& strength) {
        /*
        UpdateCertainty(first);
        UpdateCertainty(second);

        BeginCriticalSection _{ hGuard };

        if(detections.find(first->dwID) != detections.end()) {
            //AddAssociation();
        }

        if(detections.find(second->dwID) != detections.end()) {
            //AddAssociation();
        }
        */
    }

    void JSONSink::LogMessage(const LogLevel& level, const std::wstring& message) {
        BeginCriticalSection _{ hGuard };

        if(level.Enabled()) {
            std::map<std::string, std::string> msg = {};
            if(level.detail) {
                msg["detail"] = *level.detail == Detail::High ? "high" :
                                                                *level.detail == Detail::Moderate ? "moderate" : "low";
            }
            SYSTEMTIME time{};
            GetLocalTime(&time);
            msg["time"] = WidestringToString(FormatWindowsTime(time)).c_str();
            msg["message"] = WidestringToString(message).c_str();
            JSONDoc["bluespawn"]["log-messages"].push_back(msg);
        }
    }

    bool JSONSink::operator==(const LogSink& sink) const {
        return (bool) dynamic_cast<const JSONSink*>(&sink) &&
               dynamic_cast<const JSONSink*>(&sink)->wFileName == wFileName;
    }

    void JSONSink::Flush() {
        std::ofstream out(WidestringToString(wFileName));
        out << std::setw(4) << JSONDoc << std::endl;
    }
};   // namespace Log
