#include <Windows.h>

#include <sstream>

#include "util/log/DebugSink.h"
#include "user/bluespawn.h"
#include "util/Utils.h"

#define DEBUG_STREAM(...) \
    OutputDebugStringW((std::wstringstream{} << __VA_ARGS__).str().c_str())

#define DETECTION_DEBUG_STREAM(...)                                                                                  \
    DEBUG_STREAM((type == RecordType::PreScan ? L"[Pre-Scan Detection]" : L"[Detection]") << L"[ID " << detection->dwID << \
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

	void DebugSink::RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type){

		if(type == RecordType::PreScan && Bluespawn::EnablePreScanDetections || type == RecordType::PostScan){

			BeginCriticalSection __{ *detection };
			BeginCriticalSection _{ hGuard };

			DETECTION_DEBUG_STREAM(L" Detection Logged at " << FormatWindowsTime(detection->context.DetectionCreatedTime));
			if(detection->context.note){
				DETECTION_DEBUG_STREAM(L" Note: " << *detection->context.note);
			}
			if(detection->context.FirstEvidenceTime){
				DETECTION_DEBUG_STREAM(L" First Evidence: " << FormatWindowsTime(*detection->context.FirstEvidenceTime));
			}

			if(detection->context.hunts.size()){
				std::wstringstream hunts{};
				for(auto& hunt : detection->context.hunts){
					hunts << hunt << L", ";
				}
				DETECTION_DEBUG_STREAM(L" Associated Hunts: " << hunts.str());
			}

			if(detection->DetectionStale){
				DETECTION_DEBUG_STREAM(L" Detection is Stale");
			}

			DETECTION_DEBUG_STREAM(L" Detection Type: " << 
				(detection->type == DetectionType::FileDetection ? L"File" :
				 detection->type == DetectionType::ProcessDetection ? L"Process" :
				 detection->type == DetectionType::RegistryDetection ? L"Registry" :
				 detection->type == DetectionType::ServiceDetection ? L"Service" :
				 std::get<OtherDetectionData>(detection->data).DetectionType));

			DETECTION_DEBUG_STREAM(L" Detection Certainty: " << static_cast<double>(detection->info.GetCertainty()));

			auto properties{ detection->Serialize() };
			for(auto& pair : properties){
				DETECTION_DEBUG_STREAM(L"[Data] " << pair.first << L": " << pair.second);
			}
		}
	}

	void DebugSink::RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
									IN CONST std::shared_ptr<Detection>& second, IN CONST Association& a){
		BeginCriticalSection _{ hGuard };

		DEBUG_STREAM(L"[Detection][ID " << first->dwID << L"]" << L" Associated with " << second->dwID << 
					 L" with strength " << static_cast<double>(a));
	}

	void DebugSink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection){
		BeginCriticalSection __{ *detection };
		BeginCriticalSection _{ hGuard };

		DEBUG_STREAM(L"[Detection][ID " << detection->dwID << L"]" << L" now has certainty "
					 << static_cast<double>(detection->info.GetCertainty()));
	}
}
