#include "util/log/JSONSink.h"

#include <chrono>
#include <fstream>
#include <iostream>

#include "util/StringUtils.h"
#include "util/Utils.h"

#include "user/bluespawn.h"

namespace Log {

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
    }

    JSONSink::JSONSink(const std::wstring& wOutputDir) :
        thread{ CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, 0, nullptr) } {
        SYSTEMTIME time{};
        GetLocalTime(&time);
        wFileName = wOutputDir + L"\\bluespawn-" + ToWstringPad(time.wMonth) + L"-" + ToWstringPad(time.wDay) + L"-" +
                    ToWstringPad(time.wYear, 4) + L"-" + ToWstringPad(time.wHour) + ToWstringPad(time.wMinute) + L"-" +
                    ToWstringPad(time.wSecond) + L".json";
        JSONDoc = json::object();
        JSONDoc["bluespawn"] = json::object();
        JSONDoc["bluespawn"]["log-messages"] = json::array();
    }

    JSONSink::JSONSink(const std::wstring& wOutputDir, const std::wstring& wFileName) :
        wFileName{ wOutputDir + L"\\" + wFileName }, thread{
            CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, 0, nullptr)
        } {
        JSONDoc = json::object();
        JSONDoc["bluespawn"] = json::object();
        JSONDoc["bluespawn"]["log-messages"] = json::array();
    }

    JSONSink::~JSONSink() {
        std::ofstream out(WidestringToString(wFileName));
        out << std::setw(4) << JSONDoc << std::endl;
        TerminateThread(thread, 0);
    }

    void
    JSONSink::InsertElement(IN json JSONDoc, IN json parent, IN CONST std::string& name, IN CONST std::wstring& value) {
        parent[name] = WidestringToString(value).c_str();
    }

    void JSONSink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection) {
        BeginCriticalSection __{ *detection };
        BeginCriticalSection _{ hGuard };

        if(detections.find(detection->dwID) != detections.end()) {
            for(auto& item : JSONDoc["bluespawn"]["detections"]) {
                if(item["id"] == detection->dwID) {
                    const auto cert = item.find("certainty");
                    const auto rawcert = item.find("raw-certainty");
                    item.erase(cert);
                    item.erase(rawcert);
                    item["certainty"] = std::to_string(detection->info.GetCertainty());
                    item["raw-certainty"] = std::to_string(detection->info.GetIntrinsicCertainty());
                    return;
                }
            }
        }
    }

    void JSONSink::AddAssociation(IN DWORD detection_id, IN DWORD associated, IN double strength) {
        /// Note that the critical section for hGuard is already acquired as this function is only called
        /// by RecordAssociation

        for(auto& item : JSONDoc["bluespawn"]["detections"]) {
            if(item["id"] == detection_id) {
                if(item.find("associated-detections") != item.end()) {
                    /// update association strength for association already in associated-detections of detection_id
                    for(auto& child : item["associated-detections"]) {
                        if(child["id"] == associated) {
                            const auto cur_strength = child.find("strength");
                            child.erase(cur_strength);
                            child["strength"] = std::to_string(
                                (1.0 - (1 - std::stod((std::string) cur_strength.value())) * (1 - strength)));
                            return;
                        }
                    }

                    /// add new association in associated-detections of detection_id
                    item["associated-detections"].push_back(
                        { { "strength", static_cast<double>(strength) }, { "id", associated } });
                    return;
                }

                /// create associated-detections within detection_id and add new association
                item["associated-detections"] = json::array();
                item["associated-detections"].push_back(
                    { { "strength", static_cast<double>(strength) }, { "id", associated } });
                return;
            }
        }
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
            /// Delete current detection within json
            for(auto& it : JSONDoc["bluespawn"]["detections"].items()) {
                if(it.value().at("id").get<std::string>() == std::to_string(detection->dwID)) {
                    JSONDoc["bluespawn"]["detections"].erase(JSONDoc["bluespawn"]["detections"].begin() + (int&) it);
                    break;
                }
            }
        } else {
            detections.insert(detection->dwID);
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
        UpdateCertainty(first);
        UpdateCertainty(second);

        BeginCriticalSection _{ hGuard };

        if(detections.find(first->dwID) != detections.end()) {
            AddAssociation(first->dwID, second->dwID, strength);
        }

        if(detections.find(second->dwID) != detections.end()) {
            AddAssociation(second->dwID, first->dwID, strength);
        }
    }

    void JSONSink::LogMessage(const LogLevel& level, const std::wstring& message) {
        BeginCriticalSection _{ hGuard };

        if(level.Enabled()) {
            std::map<std::string, std::string> msg = {};
            if(level.detail) {
                msg["detail"] = *level.detail == Detail::High     ? "high" :
                                *level.detail == Detail::Moderate ? "moderate" :
                                                                    "low";
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
