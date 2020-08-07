#include "util/log/CLISink.h"

#include <Windows.h>

#include <iostream>

#include "util/Utils.h"

#include "user/bluespawn.h"

namespace Log {

    void CLISink::SetConsoleColor(CLISink::MessageColor color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
    }

    CLISink::CLISink() : hMutex{ CreateMutexW(nullptr, false, L"Local\\CLI-Mutex") } {}

    void CLISink::LogMessage(IN CONST LogLevel& level, IN CONST std::wstring& message) {
        AcquireMutex mutex{ hMutex };
        if(level.Enabled()) {
            SetConsoleColor(CLISink::PrependColors[static_cast<WORD>(level.severity)]);
            std::wcout << CLISink::MessagePrepends[static_cast<WORD>(level.severity)] << " ";
            SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
            std::wcout << message << std::endl;
        }
    }

    bool CLISink::operator==(IN CONST LogSink& sink) const { return (bool) dynamic_cast<const CLISink*>(&sink); }

    void CLISink::RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type) {
        if(type == RecordType::PreScan && Bluespawn::EnablePreScanDetections || type == RecordType::PostScan) {
            BeginCriticalSection _{ *detection };

            AcquireMutex mutex{ hMutex };

            SetConsoleColor(CLISink::PrependColors[4]);
            std::wcout << CLISink::MessagePrepends[4] << (type == RecordType::PreScan ? L"[Pre-Scan] " : L" ");
            SetConsoleColor(CLISink::MessageColor::LIGHTGREY);

            std::wcout << L"Detection ID: " << detection->dwID << std::endl;

            std::wcout << L"\tDetection Recorded at " << FormatWindowsTime(detection->context.DetectionCreatedTime)
                       << std::endl;
            if(detection->context.note) {
                std::wcout << L"\tNote: " << *detection->context.note << std::endl;
            }
            if(detection->context.FirstEvidenceTime) {
                std::wcout << L"\tFirst Evidence at " << FormatWindowsTime(*detection->context.FirstEvidenceTime)
                           << std::endl;
            }

            if(detection->context.hunts.size()) {
                std::wcout << L"\tDetected by: ";
                short cnt = detection->context.hunts.size();
                for(auto& hunt : detection->context.hunts) {
                    cnt--;
                    std::wcout << hunt;
                    if(cnt > 0) {
                        std::wcout << L", ";
                    }
                }
                std::wcout << std::endl;
            }

            if(detection->DetectionStale) {
                std::wcout << L"\tDetection is stale" << std::endl;
            }

            std::wcout << L"\tDetection Type: "
                       << (detection->type == DetectionType::FileDetection ?
                               L"File" :
                               detection->type == DetectionType::ProcessDetection ?
                               L"Process" :
                               detection->type == DetectionType::RegistryDetection ?
                               L"Registry" :
                               detection->type == DetectionType::ServiceDetection ?
                               L"Service" :
                               std::get<OtherDetectionData>(detection->data).DetectionType)
                       << std::endl;

            std::wcout << L"\tDetection Certainty: " << static_cast<double>(detection->info.GetCertainty())
                       << std::endl;
            std::wcout << L"\tDetection Data: " << std::endl;

            auto properties{ detection->Serialize() };
            for(auto& pair : properties) {
                std::wcout << L"\t\t" << pair.first << ": " << pair.second << std::endl;
            }
        }
    }

    void CLISink::RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                    IN CONST std::shared_ptr<Detection>& second,
                                    IN CONST Association& a) {
        AcquireMutex mutex{ hMutex };

        SetConsoleColor(CLISink::PrependColors[2]);
        std::wcout << CLISink::MessagePrepends[2];
        SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
        std::wcout << L" Detections with IDs " << first->dwID << L" and " << second->dwID << L" now are associated"
                   << L" with strength " << static_cast<double>(a) << std::endl;
    }

    void CLISink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection) {
        BeginCriticalSection _{ *detection };
        AcquireMutex mutex{ hMutex };

        SetConsoleColor(CLISink::PrependColors[2]);
        std::wcout << CLISink::MessagePrepends[2];
        SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
        std::wcout << L" Detection with ID " << detection->dwID << L" now has certainty "
                   << static_cast<double>(detection->info.GetCertainty()) << std::endl;
    }
}   // namespace Log
