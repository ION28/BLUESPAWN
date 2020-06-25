#include <Windows.h>

#include <sstream>

#include "util/log/DebugSink.h"
#include "user/bluespawn.h"
#include "common/Utils.h"

#define DEBUG_STREAM(...) \
    OutputDebugStringW((std::wstringstream{} << __VA_ARGS__).str().c_str())

#define DETECTION_DEBUG_STREAM(...)                                                                                  \
    DEBUG_STREAM((type == RecordType::PreScan ? L"[Pre-Scan Detection]" : L"[Detection]") << L"[ID " << copy.dwID << \
                 L"]" << __VA_ARGS__);

namespace Log{

	void DebugSink::LogMessage(IN CONST LogLevel& level, IN CONST std::wstring& message){
		BeginCriticalSection _{ hGuard };

		if(level.Enabled()){
			DEBUG_STREAM(DebugSink::MessagePrepends[static_cast<WORD>(level.severity)] << L" " << message);
		}
	}

	bool DebugSink::operator==(IN CONST LogSink& sink) const{
		return (bool) dynamic_cast<const DebugSink*>(&sink);
	}

	void DebugSink::RecordDetection(IN CONST std::reference_wrapper<Detection>& detection, IN RecordType type){
		BeginCriticalSection _{ hGuard };

		if(type == RecordType::PreScan && Bluespawn::EnablePreScanDetections || type == RecordType::PostScan){

			EnterCriticalSection(detection.get());
			Detection copy{ detection.get() };
			LeaveCriticalSection(detection.get());

			DETECTION_DEBUG_STREAM(L" Detection Logged at " << FormatWindowsTime(copy.context.DetectionCreatedTime));
			if(copy.context.note){
				DETECTION_DEBUG_STREAM(L" Note: " << *copy.context.note);
			}
			if(copy.context.FirstEvidenceTime){
				DETECTION_DEBUG_STREAM(L" First Evidence: " << FormatWindowsTime(*copy.context.FirstEvidenceTime));
			}

			if(detection.get().context.hunts.size()){
				std::wstringstream hunts{};
				for(auto& hunt : detection.get().context.hunts){
					hunts << hunt << L", ";
				}
				DETECTION_DEBUG_STREAM(L" Associated Hunts: " << hunts.str());
			}

			if(copy.DetectionStale){
				DETECTION_DEBUG_STREAM(L" Detection is Stale");
			}

			DETECTION_DEBUG_STREAM(L" Detection Type: " << 
				(copy.type == DetectionType::FileDetection ? L"File" :
				 copy.type == DetectionType::ProcessDetection ? L"Process" :
				 copy.type == DetectionType::RegistryDetection ? L"Registry" :
				 copy.type == DetectionType::ServiceDetection ? L"Service" :
				 std::get<OtherDetectionData>(copy.data).DetectionType));

			DETECTION_DEBUG_STREAM(L" Detection Certainty: " << static_cast<double>(copy.info.GetCertainty()));

			auto properties{ copy.Serialize() };
			for(auto& pair : properties){
				DETECTION_DEBUG_STREAM(L"[Data] " << pair.first << L": " << pair.second);
			}
		}
	}

	void DebugSink::RecordAssociation(IN CONST std::reference_wrapper<Detection>& first,
									IN CONST std::reference_wrapper<Detection>& second, IN CONST Association& a){
		BeginCriticalSection _{ hGuard };

		DEBUG_STREAM(L"[Detection][ID " << first.get().dwID << L"]" << L" Associated with " << second.get().dwID << 
					 L" with strength " << static_cast<double>(a));
	}
}