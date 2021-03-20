#include "util/log/CLISink.h"

#include <Windows.h>

#include <iostream>

#include "util/Utils.h"

#include "user/bluespawn.h"
#include "user/PyIO.h"

namespace Log {

#define PRINT_STREAM(...) \
    if(pyBuffer){ pyMessageBuffer.emplace_back((std::wstringstream{} << __VA_ARGS__).str()); } \
    else { std::wcout << __VA_ARGS__; }

#define ENDL L"\n"

    void CLISink::SetConsoleColor(CLISink::MessageColor color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
    }

    CLISink::CLISink() : pyBuffer{ dynamic_cast<const PyIO*>(&Bluespawn::io) != nullptr },
        hMutex{ CreateMutexW(nullptr, false, pyBuffer ? L"Local\\CLI-Mutex" : L"Local\\PyBuffer-Mutex") } {}

    void CLISink::LogMessage(IN CONST LogLevel& level, IN CONST std::wstring& message) {
        AcquireMutex mutex{ hMutex };
        if(level.Enabled()) {
            SetConsoleColor(CLISink::PrependColors[static_cast<WORD>(level.severity)]);
            PRINT_STREAM(CLISink::MessagePrepends[static_cast<WORD>(level.severity)] << " ");
            SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
            PRINT_STREAM(message << ENDL);
        }
    }

    bool CLISink::operator==(IN CONST LogSink& sink) const { return (bool) dynamic_cast<const CLISink*>(&sink); }

    void CLISink::RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type) {
        if(type == RecordType::PreScan && Bluespawn::EnablePreScanDetections || type == RecordType::PostScan) {
            BeginCriticalSection _{ *detection };

            AcquireMutex mutex{ hMutex };

            SetConsoleColor(CLISink::PrependColors[4]);
            PRINT_STREAM(CLISink::MessagePrepends[4] << (type == RecordType::PreScan ? L"[Pre-Scan] " : L" "));
            SetConsoleColor(CLISink::MessageColor::LIGHTGREY);

            PRINT_STREAM(L"Detection ID: " << detection->dwID << ENDL);

            PRINT_STREAM(L"\tDetection Recorded at " << FormatWindowsTime(detection->context.DetectionCreatedTime)
                       << ENDL);
            if(detection->context.note) {
                PRINT_STREAM(L"\tNote: " << *detection->context.note << ENDL);
            }
            if(detection->context.FirstEvidenceTime) {
                PRINT_STREAM(L"\tFirst Evidence at " << FormatWindowsTime(*detection->context.FirstEvidenceTime)
                           << ENDL);
            }

            if(detection->context.hunts.size()) {
                PRINT_STREAM(L"\tDetected by: ");
                short cnt = detection->context.hunts.size();
                for(auto& hunt : detection->context.hunts) {
                    cnt--;
                    PRINT_STREAM(hunt);
                    if(cnt > 0) {
                        PRINT_STREAM(L", ");
                    }
                }
                PRINT_STREAM(ENDL);
            }

            if(detection->DetectionStale) {
                PRINT_STREAM(L"\tDetection is stale" << ENDL);
            }

            PRINT_STREAM(L"\tDetection Type: "
                       << (detection->type == DetectionType::FileDetection ?
                               L"File" : detection->type == DetectionType::ProcessDetection ?
                               L"Process" : detection->type == DetectionType::RegistryDetection ?
                               L"Registry" : detection->type == DetectionType::ServiceDetection ?
                               L"Service" : std::get<OtherDetectionData>(detection->data).DetectionType)
                       << ENDL);

            PRINT_STREAM(L"\tDetection Certainty: " << static_cast<double>(detection->info.GetCertainty())
                       << ENDL);
            PRINT_STREAM(L"\tDetection Data: " << ENDL);

            auto properties{ detection->Serialize() };
            for(auto& pair : properties) {
                PRINT_STREAM(L"\t\t" << pair.first << ": " << pair.second << ENDL);
            }
        }
    }

    void CLISink::RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                    IN CONST std::shared_ptr<Detection>& second,
                                    IN CONST Association& a) {
        AcquireMutex mutex{ hMutex };

        SetConsoleColor(CLISink::PrependColors[2]);
        PRINT_STREAM(CLISink::MessagePrepends[2]);
        SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
        PRINT_STREAM(L" Detections with IDs " << first->dwID << L" and " << second->dwID << L" now are associated"
                   << L" with strength " << static_cast<double>(a) << ENDL);
    }

    void CLISink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection) {
        BeginCriticalSection _{ *detection };
        AcquireMutex mutex{ hMutex };

        SetConsoleColor(CLISink::PrependColors[2]);
        PRINT_STREAM(CLISink::MessagePrepends[2]);
        SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
        PRINT_STREAM(L" Detection with ID " << detection->dwID << L" now has certainty "
                   << static_cast<double>(detection->info.GetCertainty()) << ENDL);
    }
}   // namespace Log
