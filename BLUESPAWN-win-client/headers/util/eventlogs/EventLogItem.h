#pragma once
#include <string>
#include <unordered_map>
#include <Windows.h>
#include <winevt.h>
#include "util/wrappers.hpp"

namespace EventLogs {

	class EventWrapper : public GenericWrapper<EVT_HANDLE> {
	public:
		EventWrapper(EVT_HANDLE handle) :
			GenericWrapper(handle, std::function<void(EVT_HANDLE)>(EvtClose), INVALID_HANDLE_VALUE){};
	};

	class EventLogItem {
		public:
			std::wstring GetProperty(std::wstring prop) const;
			std::unordered_map<std::wstring, std::wstring> GetProperties() const;
			std::wstring GetChannel() const;
			std::wstring GetTimeCreated() const;
			std::wstring GetXML() const;
			unsigned int GetEventID() const;
			unsigned int GetEventRecordID() const;

			void SetProperty(std::wstring& property, std::wstring& value);
			void SetChannel(std::wstring& channel);
			void SetTimeCreated(std::wstring& time);
			void SetXML(std::wstring& xml);
			void SetEventID(unsigned int id);
			void SetEventRecordID(unsigned int id);

		private:
			unsigned int eventID;
			unsigned int eventRecordID;
			std::wstring timeCreated;
			std::wstring channel;
			std::wstring rawXML;
			std::unordered_map<std::wstring, std::wstring> props;
	};

}