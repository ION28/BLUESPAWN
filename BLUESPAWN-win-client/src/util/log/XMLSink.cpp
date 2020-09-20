#include "util/log/XMLSink.h"

#include <chrono>
#include <iostream>

#include "util/StringUtils.h"
#include "util/Utils.h"

#include "user/bluespawn.h"

namespace Log {

    void UpdateLog(XMLSink* sink) {
        HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
        while(true) {
            WaitForSingleObject(hRecordEvent, INFINITE);
            sink->Flush();
        }
    }

    XMLSink::XMLSink() :
        Root{ XMLDoc.NewElement("bluespawn") }, LogRoot{ XMLDoc.NewElement("log-messages") }, thread{
            CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, CREATE_SUSPENDED, nullptr)
        } {
        SYSTEMTIME time{};
        GetLocalTime(&time);
        wFileName = L"bluespawn-" + ToWstringPad(time.wMonth) + L"-" + ToWstringPad(time.wDay) + L"-" +
                    ToWstringPad(time.wYear, 4) + L"-" + ToWstringPad(time.wHour) + ToWstringPad(time.wMinute) + L"-" +
                    ToWstringPad(time.wSecond) + L".xml";
        XMLDoc.InsertEndChild(Root);
        Root->InsertEndChild(LogRoot);
        ResumeThread(thread);
    }

    XMLSink::XMLSink(const std::wstring& wOutputDir) :
        Root{ XMLDoc.NewElement("bluespawn") }, LogRoot{ XMLDoc.NewElement("log-messages") }, thread{
            CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, 0, nullptr)
        } {
        SYSTEMTIME time{};
        GetLocalTime(&time);
        wFileName = wOutputDir + L"\\bluespawn-" + ToWstringPad(time.wMonth) + L"-" + ToWstringPad(time.wDay) + L"-" +
                    ToWstringPad(time.wYear, 4) + L"-" + ToWstringPad(time.wHour) + ToWstringPad(time.wMinute) + L"-" +
                    ToWstringPad(time.wSecond) + L".xml";
        XMLDoc.InsertEndChild(Root);
    }

    XMLSink::XMLSink(const std::wstring& wOutputDir, const std::wstring& wFileName) :
        Root{ XMLDoc.NewElement("bluespawn") }, wFileName{ wOutputDir + L"\\" + wFileName }, LogRoot{ XMLDoc.NewElement(
                                                                                                 "log-messages") },
        thread{ CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, 0, nullptr) } {
        XMLDoc.InsertEndChild(Root);
    }

    XMLSink::~XMLSink() {
        XMLDoc.SaveFile(WidestringToString(wFileName).c_str());
        TerminateThread(thread, 0);
    }

    void InsertElement(IN tinyxml2::XMLDocument& XMLDoc,
                       IN tinyxml2::XMLElement* parent,
                       IN CONST std::string& name,
                       IN CONST std::wstring& value) {
        auto elem{ XMLDoc.NewElement(name.c_str()) };
        elem->SetText(WidestringToString(value).c_str());
        parent->InsertEndChild(elem);
    }

    void XMLSink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection) {
        BeginCriticalSection __{ *detection };
        BeginCriticalSection _{ hGuard };
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
    }

    void AddAssociation(IN tinyxml2::XMLDocument& doc, IN tinyxml2::XMLElement* to, IN DWORD id, IN double strength) {
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
    }

    void XMLSink::RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type) {
        if(type == RecordType::PreScan && !Bluespawn::EnablePreScanDetections) {
            return;
        }

        BeginCriticalSection __{ *detection };
        BeginCriticalSection _{ hGuard };

        tinyxml2::XMLElement* detect{ nullptr };
        if(detections.find(detection->dwID) != detections.end()) {
            detect = detections.at(detection->dwID);
            detect->DeleteChildren();
        } else {
            detect = XMLDoc.NewElement("detection");
            detections.emplace(detection->dwID, detect);
            Root->InsertEndChild(detect);
        }

        if(type == RecordType::PreScan) {
            detect->SetAttribute("prescan", true);
        }

        detect->SetAttribute("type",
                             (detection->type == DetectionType::FileDetection ?
                                  "File" :
                              detection->type == DetectionType::ProcessDetection ?
                                  "Process" :
                              detection->type == DetectionType::RegistryDetection ?
                                  "Registry" :
                              detection->type == DetectionType::ServiceDetection ?
                                  "Service" :
                                  WidestringToString(std::get<OtherDetectionData>(detection->data).DetectionType))
                                 .c_str());

        detect->SetAttribute("id", std::to_string(detection->dwID).c_str());
        detect->SetAttribute("time",
                             WidestringToString(FormatWindowsTime(detection->context.DetectionCreatedTime)).c_str());

        if(detection->context.FirstEvidenceTime) {
            InsertElement(XMLDoc, detect, "first-evidence-time",
                          FormatWindowsTime(*detection->context.FirstEvidenceTime));
        }

        if(detection->context.note) {
            InsertElement(XMLDoc, detect, "note", *detection->context.note);
        }

        InsertElement(XMLDoc, detect, "certainty", std::to_wstring(detection->info.GetCertainty()));
        InsertElement(XMLDoc, detect, "raw-certainty", std::to_wstring(detection->info.GetIntrinsicCertainty()));

        if(detection->context.hunts.size()) {
            auto hunts{ XMLDoc.NewElement("associated-hunts") };
            for(const auto& hunt : detection->context.hunts) {
                InsertElement(XMLDoc, hunts, "hunt", hunt);
            }
            detect->InsertEndChild(hunts);
        }

        auto data{ XMLDoc.NewElement("associated-data") };
        for(const auto& entry : detection->Serialize()) {
            auto elem{ XMLDoc.NewElement("property") };
            elem->SetAttribute("name", WidestringToString(entry.first).c_str());
            elem->SetText(WidestringToString(entry.second).c_str());
            data->InsertEndChild(elem);
        }
        detect->InsertEndChild(data);

        auto assoc{ detection->info.GetAssociations() };
        if(assoc.size()) {
            auto assocations{ XMLDoc.NewElement("associated-detections") };
            for(const auto& det : assoc) {
                auto elem{ XMLDoc.NewElement("association") };
                elem->SetAttribute("strength", static_cast<double>(det.second));
                elem->SetText(std::to_string(det.first->dwID).c_str());
                assocations->InsertEndChild(elem);
            }
            detect->InsertEndChild(assocations);
        }
    }

    void XMLSink::RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                    IN CONST std::shared_ptr<Detection>& second,
                                    IN CONST Association& strength) {
        UpdateCertainty(first);
        UpdateCertainty(second);

        BeginCriticalSection _{ hGuard };

        if(detections.find(first->dwID) != detections.end()) {
            AddAssociation(XMLDoc, detections.at(first->dwID), second->dwID, strength);
        }

        if(detections.find(second->dwID) != detections.end()) {
            AddAssociation(XMLDoc, detections.at(second->dwID), first->dwID, strength);
        }
    }

    void XMLSink::LogMessage(const LogLevel& level, const std::wstring& message) {
        BeginCriticalSection _{ hGuard };

        if(level.Enabled()) {
            auto msg = XMLDoc.NewElement(MessageTags[static_cast<DWORD>(level.severity)].c_str());
            if(level.detail) {
                msg->SetAttribute("detail", *level.detail == Detail::High     ? "high" :
                                            *level.detail == Detail::Moderate ? "moderate" :
                                                                                "low");
            }

            SYSTEMTIME time{};
            GetLocalTime(&time);
            msg->SetAttribute("time", WidestringToString(FormatWindowsTime(time)).c_str());

            msg->SetText(WidestringToString(message).c_str());
            LogRoot->InsertEndChild(msg);
        }
    }

    bool XMLSink::operator==(const LogSink& sink) const {
        return (bool) dynamic_cast<const XMLSink*>(&sink) &&
               dynamic_cast<const XMLSink*>(&sink)->wFileName == wFileName;
    }

    void XMLSink::Flush() { XMLDoc.SaveFile(WidestringToString(wFileName).c_str()); }
};   // namespace Log
