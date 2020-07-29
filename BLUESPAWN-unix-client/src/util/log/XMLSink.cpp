#include "util/log/XMLSink.h"
#include "common/StringUtils.h"
#include "monitor/listen/Events.h"

#include <chrono>
#include <iostream>
#include "common/Utils.h"
#include <pthread.h>
#include <signal.h>
#include <stddef.h>

namespace Log{

	std::wstring ToWstringPad(unsigned int value, size_t length=2){
		wchar_t* buf = new wchar_t[length + 1];
		swprintf(buf, length + 1, (L"%0" + std::to_wstring(length) + L"d").c_str(), value);
		std::wstring str = buf;
		delete[] buf;
		return str;
	}

	std::string ToStringPad(unsigned int value, size_t length=2){
		char * buf = new char[length+1];
		snprintf(buf, length + 1, ("%0" + std::to_string(length) + "d").c_str(), value);
		std::string str = buf;
		delete[] buf;
		return str;
	}

	void * UpdateLog(void * arg){
		XMLSink * sink = (XMLSink*) arg;
		Events::EventHandle * handle = sink->GetEventHandle();
		while(true){
			Events::WaitForSingleObject(handle, INFINITE);
			sink->Flush();
		}
	}

	XMLSink::XMLSink() :
		Root{ XMLDoc.NewElement("bluespawn") },
		hRecordEvent{Events::CreateEvent()}{
		pthread_mutex_init(&this->hMutex, NULL);
		time_t curr = time(NULL);
		struct tm * time = localtime(&curr);
		wFileName = "bluespawn-" + ToStringPad(time->tm_mon) + "-" + ToStringPad(time->tm_mday) + "-" + ToStringPad(time->tm_year, 4) + "-"
			+ ToStringPad(time->tm_hour) + ToStringPad(time->tm_min) + "-" + ToStringPad(time->tm_sec) + ".xml";
		XMLDoc.InsertEndChild(Root);
		pthread_create(&this->thread, NULL, UpdateLog, this);
	}

	XMLSink::XMLSink(const std::string& wFileName) :
		Root { XMLDoc.NewElement("bluespawn") },
		wFileName{ wFileName },
		hRecordEvent{Events::CreateEvent()}{
		pthread_mutex_init(&this->hMutex, NULL);
		pthread_create(&this->thread, NULL, UpdateLog, this);
		XMLDoc.InsertEndChild(Root);
	}

	XMLSink::~XMLSink(){
		XMLDoc.SaveFile(wFileName.c_str());
		//TerminateThread(thread, 0);
		//TOOD
		pthread_kill(this->thread, SIGKILL);
		Events::CloseHandle(this->hRecordEvent);
		pthread_mutex_destroy(&this->hMutex);
	}

	Events::EventHandle * XMLSink::GetEventHandle(){
		return this->hRecordEvent;
	}

	tinyxml2::XMLElement* CreateDetctionXML(const std::shared_ptr<DETECTION>& detection, tinyxml2::XMLDocument& XMLDoc){
		auto detect = XMLDoc.NewElement("detection");
		if(detection->Type == DetectionType::File){
			detect->SetAttribute("type", "File");
			auto FileDetection = std::static_pointer_cast<FILE_DETECTION>(detection);
			auto Name = XMLDoc.NewElement("name");
			auto Path = XMLDoc.NewElement("path");
			auto MD5 = XMLDoc.NewElement("md5");
			auto SHA1 = XMLDoc.NewElement("sha1");
			auto SHA256 = XMLDoc.NewElement("sha256");
			auto Created = XMLDoc.NewElement("created");
			auto Modified = XMLDoc.NewElement("modified");
			auto Accessed = XMLDoc.NewElement("accessed");
			Name->SetText(FileDetection->wsFileName.c_str());
			Path->SetText(FileDetection->wsFilePath.c_str());
			MD5->SetText(FileDetection->md5.c_str());
			SHA1->SetText(FileDetection->sha1.c_str());
			SHA256->SetText(FileDetection->sha256.c_str());
			Created->SetText(FileDetection->created.c_str());
			Modified->SetText(FileDetection->modified.c_str());
			Accessed->SetText(FileDetection->accessed.c_str());
			detect->InsertEndChild(Name);
			detect->InsertEndChild(Path);
			detect->InsertEndChild(MD5);
			detect->InsertEndChild(SHA1);
			detect->InsertEndChild(SHA256);
			detect->InsertEndChild(Created);
			detect->InsertEndChild(Modified);
			detect->InsertEndChild(Accessed);
		} else if(detection->Type == DetectionType::Process){
			detect->SetAttribute("type", "Process");
			auto ProcessDetection = std::static_pointer_cast<PROCESS_DETECTION>(detection);
			auto Path = XMLDoc.NewElement("path");
			auto Cmd = XMLDoc.NewElement("cmdline");
			auto Pid = XMLDoc.NewElement("pid");
			Path->SetText(ProcessDetection->wsImagePath.c_str());
			Cmd->SetText(ProcessDetection->wsCmdline.c_str());
			Pid->SetText(std::to_string(ProcessDetection->PID).c_str());
			detect->InsertEndChild(Path);
			detect->InsertEndChild(Cmd);
			detect->InsertEndChild(Pid);
		} else if(detection->Type == DetectionType::Service){
			detect->SetAttribute("type", "Service");
			auto ServiceDetection = std::static_pointer_cast<SERVICE_DETECTION>(detection);
			auto Name = XMLDoc.NewElement("name");
			auto Path = XMLDoc.NewElement("path");
			auto Dll = XMLDoc.NewElement("dll");
			auto Pid = XMLDoc.NewElement("pid");
			Name->SetText(ServiceDetection->wsServiceName.c_str());
			Path->SetText(ServiceDetection->wsServiceExecutablePath.c_str());
			Dll->SetText(ServiceDetection->wsServiceDll.c_str());
			Pid->SetText(std::to_string(ServiceDetection->ServicePID).c_str());
			detect->InsertEndChild(Name);
			detect->InsertEndChild(Path);
			detect->InsertEndChild(Dll);
			detect->InsertEndChild(Pid);
		} else if(detection->Type == DetectionType::Event){
			detect->SetAttribute("type", "Event");
			auto EventDetection = std::static_pointer_cast<EVENT_DETECTION>(detection);
			auto ID = XMLDoc.NewElement("id");
			auto RecordID = XMLDoc.NewElement("recordid");
			auto Time = XMLDoc.NewElement("time");
			auto Channel = XMLDoc.NewElement("channel");
			auto Raw = XMLDoc.NewElement("raw");
			ID->SetText(std::to_string(EventDetection->eventID).c_str());
			RecordID->SetText(std::to_string(EventDetection->eventRecordID).c_str());
			Time->SetText(EventDetection->timeCreated.c_str());
			Channel->SetText(EventDetection->channel.c_str());
			Raw->SetText(EventDetection->rawXML.c_str());
			detect->InsertEndChild(ID);
			detect->InsertEndChild(RecordID);
			detect->InsertEndChild(Time);
			detect->InsertEndChild(Channel);
			detect->InsertEndChild(Raw);
			for(auto key : EventDetection->params){
				auto name = key.first;
				auto idx1 = name.find("'") + 1;
				auto tag = XMLDoc.NewElement(name.substr(idx1, name.find_last_of("'") - idx1).c_str());
				tag->SetText(key.second.c_str());
				detect->InsertEndChild(tag);
			}
		}
		return detect;
	}

	void XMLSink::LogMessage(const LogLevel& level, const std::string& message, const std::optional<HuntInfo> info, const std::vector<std::shared_ptr<DETECTION>>& detections){
		auto mutex = AcquireMutex(hMutex);
		if(level.Enabled() && level.severity == Severity::LogHunt && info){
			auto hunt = XMLDoc.NewElement("hunt");
			hunt->SetAttribute("agressiveness", info->HuntAggressiveness == Aggressiveness::Intensive ? "Intensive" :
				info->HuntAggressiveness == Aggressiveness::Normal ? "Normal" : "Cursory");
			hunt->SetAttribute("categories", static_cast<int64_t>(info->HuntCategories));
			hunt->SetAttribute("datasources", static_cast<int64_t>(info->HuntDatasources));
			hunt->SetAttribute("tactics", static_cast<int64_t>(info->HuntTactics));
			hunt->SetAttribute("time", FormatStatTime(&info->HuntStartTime).c_str());
			hunt->SetAttribute("datetime", FormatStatTime(&info->HuntStartTime).c_str());

			auto name = XMLDoc.NewElement("name");
			name->SetText(info->HuntName.c_str());
			hunt->InsertFirstChild(name);

			if(message.length() > 0){
				auto msg = XMLDoc.NewElement("message");
				msg->SetText(message.c_str());
				hunt->InsertEndChild(msg);
			}
			for(auto detection : detections){
				hunt->InsertEndChild(CreateDetctionXML(detection, XMLDoc));
			}

			Root->InsertEndChild(hunt);
		} else if(level.Enabled()) {
			auto msg = XMLDoc.NewElement(MessageTags[static_cast<unsigned int>(level.severity)].c_str());
			time_t t = time(NULL);
			struct tm * st = localtime(&t);
			msg->SetAttribute("time", FormatStatTime(st).c_str());
			msg->SetText(message.c_str());
			Root->InsertEndChild(msg);
		}
	}

	bool XMLSink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const XMLSink*>(&sink) && dynamic_cast<const XMLSink*>(&sink)->wFileName == wFileName;
	}

	void XMLSink::Flush(){
		XMLDoc.SaveFile(wFileName.c_str());
	}
};
