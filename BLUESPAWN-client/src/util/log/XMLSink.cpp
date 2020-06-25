#include "util/log/XMLSink.h"
#include "common/StringUtils.h"
#include "common/Utils.h"

#include <chrono>
#include <iostream>

namespace Log{

	void UpdateLog(XMLSink* sink){
		HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
		while(true){
			WaitForSingleObject(hRecordEvent, INFINITE);
			sink->Flush();
		}
	}

	XMLSink::XMLSink() :
		Root{ XMLDoc.NewElement("bluespawn") },
		thread{ CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, CREATE_SUSPENDED, nullptr) }{
		SYSTEMTIME time{};
		GetLocalTime(&time);
		wFileName = L"bluespawn-" + FormatWindowsTime(time) + L".xml";
		XMLDoc.InsertEndChild(Root);
		ResumeThread(thread);
	}

	XMLSink::XMLSink(const std::wstring& wFileName) :
		Root { XMLDoc.NewElement("bluespawn") },
		wFileName{ wFileName },
		thread{ CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, 0, nullptr) }{
		XMLDoc.InsertEndChild(Root);
	}

	XMLSink::~XMLSink(){
		XMLDoc.SaveFile(WidestringToString(wFileName).c_str());
		TerminateThread(thread, 0);
	}

	void InsertElement(IN tinyxml2::XMLDocument& XMLDoc, IN tinyxml2::XMLElement* parent, IN CONST std::string& name,
					   IN CONST std::wstring& value){
		auto elem{ XMLDoc.NewElement(name.c_str()) };
		elem->SetText(WidestringToString(value).c_str());
		parent->InsertEndChild(elem);
	}

	void AddAssociation(IN tinyxml2::XMLDocument& doc, IN tinyxml2::XMLElement* to, IN DWORD id, IN double strength){
		for(auto child{ to->FirstChildElement() }; child; child = child->NextSiblingElement()){
			if(child->GetText() == std::string{ "associated-detections" }){
				for(auto elem{ child->FirstChildElement() }; elem; elem = elem->NextSiblingElement()){
					if(elem->GetText() == std::to_string(id)){
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

	void XMLSink::RecordDetection(IN CONST std::reference_wrapper<Detection>& detection, IN RecordType type){
		BeginCriticalSection _{ hGuard };

		EnterCriticalSection(detection.get());
		Detection copy{ detection.get() };
		LeaveCriticalSection(detection.get());

		tinyxml2::XMLElement* detect{ nullptr };
		if(detections.find(copy.dwID) != detections.end()){
			detect = detections.at(copy.dwID);
			detect->DeleteChildren();
		} else{
			detect = XMLDoc.NewElement("detection");
			Root->InsertEndChild(detect);
		}

		if(type == RecordType::PreScan){
			detect->SetAttribute("prescan", true);
		}

		detect->SetAttribute("type", (
			copy.type == DetectionType::FileDetection ? "File" :
			copy.type == DetectionType::ProcessDetection ? "Process" :
			copy.type == DetectionType::RegistryDetection ? "Registry" :
			copy.type == DetectionType::ServiceDetection ? "Service" :
			WidestringToString(std::get<OtherDetectionData>(copy.data).DetectionType)
		).c_str());

		detect->SetAttribute("id", std::to_string(copy.dwID).c_str());
		detect->SetAttribute("time", WidestringToString(FormatWindowsTime(copy.context.DetectionCreatedTime)).c_str());

		if(copy.context.FirstEvidenceTime){
			InsertElement(XMLDoc, detect, "first-evidence-time", FormatWindowsTime(*copy.context.FirstEvidenceTime));
		}

		if(copy.context.note){
			InsertElement(XMLDoc, detect, "note", *copy.context.note);
		}

		InsertElement(XMLDoc, detect, "certainty", std::to_wstring(copy.info.GetCertainty()));

		if(copy.context.hunts.size()){
			auto hunts{ XMLDoc.NewElement("associated-hunts") };
			for(const auto& hunt : copy.context.hunts){
				InsertElement(XMLDoc, hunts, "hunt", hunt);
			}
			detect->InsertEndChild(hunts);
		}

		auto data{ XMLDoc.NewElement("associated-data") };
		for(const auto& entry : copy.Serialize()){
			auto elem{ XMLDoc.NewElement("property") };
			elem->SetAttribute("name", WidestringToString(entry.first).c_str());
			data->InsertEndChild(elem);
		}
		detect->InsertEndChild(data);

		auto assoc{ copy.info.GetAssociations() };
		if(assoc.size()){
			auto assocations{ XMLDoc.NewElement("associated-detections") };
			for(const auto& det : assoc){
				auto elem{ XMLDoc.NewElement("association") };
				elem->SetAttribute("strength", static_cast<double>(det.second));
				elem->SetText(std::to_string(det.first.get().dwID).c_str());
				assocations->InsertEndChild(elem);
			}
			detect->InsertEndChild(assocations);
		}
	}

	void XMLSink::RecordAssociation(IN CONST std::reference_wrapper<Detection>& first,
									IN CONST std::reference_wrapper<Detection>& second,
									IN CONST Association& strength){
		BeginCriticalSection _{ hGuard };

		if(detections.find(first.get().dwID) != detections.end()){
			AddAssociation(XMLDoc, detections.at(first.get().dwID), second.get().dwID, strength);
		}

		if(detections.find(second.get().dwID) != detections.end()){
			AddAssociation(XMLDoc, detections.at(second.get().dwID), first.get().dwID, strength);
		}
	}

	void XMLSink::LogMessage(const LogLevel& level, const std::wstring& message){
		BeginCriticalSection _{ hGuard };
		
		if(level.Enabled()) {
			auto msg = XMLDoc.NewElement(MessageTags[static_cast<DWORD>(level.severity)].c_str());
			if(level.detail){
				msg->SetAttribute("detail", *level.detail == Detail::High ? "high" :
				                            *level.detail == Detail::Moderate ? "moderate" : "low");
			}

			SYSTEMTIME time{};
			GetLocalTime(&time);
			msg->SetAttribute("time", WidestringToString(FormatWindowsTime(time)).c_str());

			msg->SetText(message.c_str());
			Root->InsertEndChild(msg);
		}
	}

	bool XMLSink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const XMLSink*>(&sink) &&
			dynamic_cast<const XMLSink*>(&sink)->wFileName == wFileName;
	}

	void XMLSink::Flush(){
		XMLDoc.SaveFile(WidestringToString(wFileName).c_str());
	}
};