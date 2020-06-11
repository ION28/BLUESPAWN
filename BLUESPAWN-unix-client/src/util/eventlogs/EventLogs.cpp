#include "util/eventlogs/EventLogs.h"
#include "common/StringUtils.h"
#include "reaction/Detections.h"
#include "util/log/Log.h"
#include "common/Utils.h"

const int SIZE_DATA = 4096;
const int ARRAY_SIZE = 10;

namespace EventLogs {
/*
	std::optional<std::string> EventLogs::GetEventParam(const EventWrapper& hEvent, const std::string& param) {
		auto queryParam = param.c_str();
		EventWrapper hContext = EvtCreateRenderContext(1, &queryParam, EvtRenderContextValues);
		if (!hContext){
			LOG_ERROR("EventLogs::GetEventParam: EvtCreateRenderContext failed with " + std::to_string(errno));
			return std::nullopt;
		}

		unsigned int dwBufferSize{};
		if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, nullptr, &dwBufferSize, nullptr)){
			if(ERROR_INSUFFICIENT_BUFFER == errno){
				auto pRenderedValues = AllocationWrapper{ malloc(dwBufferSize), dwBufferSize, AllocationWrapper::MALLOC };
				if(pRenderedValues){
					if(EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferSize, nullptr)){*/
						
						/*
						Table of variant members found here: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ns-winevt-evt_variant
						Table of type values found here: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_variant_type
						*/
/*
						PEVT_VARIANT result = reinterpret_cast<PEVT_VARIANT>((void*) pRenderedValues);
						if(result->Type == EvtVarTypeString)
							return std::string(result->StringVal);
						else if(result->Type == EvtVarTypeFileTime) {
							wchar_t ar[30];
							_ui64tow(result->FileTimeVal, ar, 10);
							return ar;
						} else if(result->Type == EvtVarTypeUInt16) {
							return std::to_string(result->UInt16Val);
						} else if (result->Type == EvtVarTypeUInt32) {
							return std::to_string(result->UInt32Val);
						} else if(result->Type == EvtVarTypeUInt64) {
							return std::to_string(result->UInt64Val);
						} else if(result->Type == EvtVarTypeNull)
							return "NULL";
						else {
							return "Unknown VARIANT: " + std::to_string(result->Type);
						}
					}
				}
			}
		}
		return std::nullopt;
	}

	std::optional<std::string> EventLogs::GetEventXML(const EventWrapper& hEvent){
		unsigned int dwBufferSize = 0;
		if(!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, nullptr, &dwBufferSize, nullptr)){
			if (ERROR_INSUFFICIENT_BUFFER == errno){
				auto pRenderedContent = AllocationWrapper{ HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize), dwBufferSize, AllocationWrapper::HEAP_ALLOC };
				if (pRenderedContent){
					if(EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferSize, nullptr)){
						return reinterpret_cast<char*>((void*)pRenderedContent);
					}
				}
			}
		}

		return std::nullopt;
	}

	// Enumerate all the events in the result set. 
	std::vector<EventLogItem> EventLogs::ProcessResults(const EventWrapper& hResults, const std::vector<XpathQuery>& filters) {
		EVT_HANDLE hEvents[ARRAY_SIZE];

		std::vector<EventLogItem> results;
		std::vector<std::string> params;
		for(auto query : filters){
			if(!query.SearchesByValue()){
				params.push_back(query.ToString());
			}
		}

		unsigned int dwReturned{};
		while(EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned)){
			for(unsigned int i = 0; i < dwReturned; i++) {

				auto item = EventToEventLogItem(hEvents[i], params);
				if(item){
					results.push_back(*item);
				}

				EvtClose(hEvents[i]);
				hEvents[i] = NULL;
			}
		}

		for(unsigned i = 0; i < ARRAY_SIZE; i++){
			if(hEvents[i]){
				EvtClose(hEvents[i]);
			}
		}

		if(errno != ERROR_NO_MORE_ITEMS){
			LOG_ERROR("EventLogs::ProcessResults: EvtNext failed with " << errno);
		}

		return results;
	}

	std::optional<EventLogItem> EventToEventLogItem(const EventWrapper& hEvent, const std::vector<std::string>& params){
		unsigned int status = ERROR_SUCCESS;

		std::optional<std::string> eventIDStr, eventRecordIDStr, timeCreated, channel, rawXML;

		if (std::nullopt == (eventIDStr = GetEventParam(hEvent, "Event/System/EventID")))
			return std::nullopt;
		if (std::nullopt == (eventRecordIDStr = GetEventParam(hEvent, "Event/System/EventRecordID")))
			return std::nullopt;
		if (std::nullopt == (timeCreated = GetEventParam(hEvent, "Event/System/TimeCreated/@SystemTime")))
			return std::nullopt;
		if (std::nullopt == (channel = GetEventParam(hEvent, "Event/System/Channel")))
			return std::nullopt;
		if (std::nullopt == (rawXML = GetEventXML(hEvent)))
			return std::nullopt;

		EventLogItem pItem{};

		// Provide values for filtered parameters
		for (std::string key : params) {
			std::optional<std::string> val = GetEventParam(hEvent, key);
			if (!val) {
				return std::nullopt;
			}

			pItem.SetProperty(key, *val);
		}

		pItem.SetEventID(std::stoul(*eventIDStr));
		pItem.SetEventRecordID(std::stoul(*eventRecordIDStr));
		pItem.SetTimeCreated(FormatWindowsTime(*timeCreated));
		pItem.SetChannel(*channel);
		pItem.SetXML(*rawXML);

		return pItem;
	}

	std::vector<EventLogItem> EventLogs::QueryEvents(const std::string& channel, unsigned int id, const std::vector<XpathQuery>& filters) {

		std::vector<EventLogItem> items;

		auto query = std::string("Event/System[EventID=") + std::to_string(id) + std::string("]");
		for (auto param : filters)
			query += " and " + param.ToString();

		EventWrapper hResults = EvtQuery(NULL, channel.c_str(), query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);
		if (NULL == hResults) {
			if (ERROR_EVT_CHANNEL_NOT_FOUND == errno)
				LOG_ERROR("EventLogs::QueryEvents: The channel was not found.");
			else if (ERROR_EVT_INVALID_QUERY = errno)
				LOG_ERROR("EventLogs::QueryEvents: The query " << query << " is not valid.");
			else
				LOG_ERROR("EventLogs::QueryEvents: EvtQuery failed with " << errno);
		}
		else {
			items = ProcessResults(hResults, filters);
		}

		return items;
	}

	std::vector<EventSubscription> subscriptions = {};

	std::optional<std::reference_wrapper<EventSubscription>> EventLogs::SubscribeToEvent(const std::string& pwsPath, 
		unsigned int id, const std::function<void(EventLogItem)>& callback, const std::vector<XpathQuery>& filters){
		auto query = std::string("Event/System[EventID=") + std::to_string(id) + std::string("]");
		for (auto param : filters)
			query += " and " + param.ToString();

		subscriptions.emplace_back(EventSubscription{ callback });
		auto& eventSub = subscriptions[subscriptions.size() - 1];

		EventWrapper hSubscription = EvtSubscribe(NULL, NULL, pwsPath.c_str(), query.c_str(), NULL, &subscriptions[subscriptions.size() - 1], 
			CallbackWrapper, EvtSubscribeToFutureEvents);
		eventSub.setSubHandle(hSubscription);

		if(!hSubscription){
			if (ERROR_EVT_CHANNEL_NOT_FOUND == errno)
				LOG_ERROR("EventLogs::SubscribeToEvent: Channel was not found.");
			else if (ERROR_EVT_INVALID_QUERY == errno)
				LOG_ERROR("EventLogs::SubscribeToEvent: query " << query << " is not valid.");
			else
				LOG_ERROR("EventLogs::SubscribeToEvent: EvtSubscribe failed with " << errno);

			return std::nullopt;
		}

		return eventSub;
	}

	std::shared_ptr<EVENT_DETECTION> EventLogs::EventLogItemToDetection(const EventLogItem& pItem) {
		auto detect = std::make_shared<EVENT_DETECTION>(0, 0, "", "", "");

		detect->eventID = pItem.GetEventID();
		detect->channel = pItem.GetChannel();
		detect->eventRecordID = pItem.GetEventRecordID();
		detect->timeCreated = pItem.GetTimeCreated();
		detect->rawXML = pItem.GetXML();
		detect->params = pItem.GetProperties();

		return detect;
	}

	bool IsChannelOpen(const std::string& channel) {
		EVT_HANDLE hChannel = NULL;
		unsigned int status = ERROR_SUCCESS;
		PEVT_VARIANT pProperty = NULL;  
		PEVT_VARIANT pTemp = NULL;
		unsigned int dwBufferSize = 0;
		unsigned int dwBufferUsed = 0;

		// Open the channel config
		hChannel = EvtOpenChannelConfig(NULL, channel.c_str(), 0);
		if (NULL == hChannel)
		{
			LOG_ERROR("EventLogs::IsChannelOpen: EvtOpenChannelConfig failed with " + std::to_string(errno) + " for channel " + channel);
			return false;
		}

		// Attempt to get the channel property
		if (!EvtGetChannelConfigProperty(hChannel, EvtChannelConfigEnabled, 0, dwBufferSize, pProperty, &dwBufferUsed))
		{
			status = errno;
			if (ERROR_INSUFFICIENT_BUFFER == status) {
				dwBufferSize = dwBufferUsed;
				pTemp = (PEVT_VARIANT)realloc(pProperty, dwBufferSize);

				if (pTemp) {
					pProperty = pTemp;
					pTemp = NULL;
					EvtGetChannelConfigProperty(hChannel, EvtChannelConfigEnabled, 0, dwBufferSize, pProperty, &dwBufferUsed);
				}
				else {
					if (pProperty)
						free(pProperty);

					LOG_ERROR("EventLogs::IsChannelOpen: realloc failed for channel " + channel);
					return false;
				}
			}

			if (ERROR_SUCCESS != (status = errno)) {
				LOG_ERROR("EventLogs::IsChannelOpen: EvtGetChannelConfigProperty failed with " + std::to_string(errno) + " for channel " + channel);
				return false;
			}

		}
		if (pProperty)
			free(pProperty);

		return pProperty->BooleanVal;
	}

	bool OpenChannel(const std::string& channel) {
		EVT_HANDLE hChannel = NULL;
		unsigned int status = ERROR_SUCCESS;
		EVT_VARIANT ChannelProperty;
		unsigned int dwBufferSize = sizeof(EVT_VARIANT);
		unsigned int dwBufferUsed = 0;
		hChannel = EvtOpenChannelConfig(NULL, channel.c_str(), 0);
		if (NULL == hChannel)
		{
			LOG_ERROR("EventLogs::OpenChannel: EvtOpenChannelConfig failed with " + std::to_string(errno) + " for channel " + channel);
			return false;
		}
		RtlZeroMemory(&ChannelProperty, dwBufferSize);

		ChannelProperty.Type = EvtVarTypeBoolean;
		ChannelProperty.BooleanVal = TRUE;

		if (!EvtSetChannelConfigProperty(hChannel, EvtChannelConfigEnabled, 0, &ChannelProperty))
		{
			LOG_ERROR("EventLogs::OpenChannel: EvtSetChannelConfigProperty failed with " + std::to_string(errno) + " for channel " + channel);
			return false;
		}
		if (!EvtSaveChannelConfig(hChannel, 0))
		{
			LOG_ERROR("EventLogs::OpenChannel: EvtSaveChannelConfig failed with " + std::to_string(errno) + " for channel " + channel);
			return false;
		}

		return true;
	}
*/
}