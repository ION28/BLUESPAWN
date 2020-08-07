#include "util/eventlogs/EventLogs.h"

#include <string>

#include "util/StringUtils.h"
#include "util/Utils.h"
#include "util/log/Log.h"

const int SIZE_DATA = 4096;
const int ARRAY_SIZE = 10;

namespace EventLogs {

    /**
	 * The callback function directly called by event subscriptions.
	 * In turn it calls the EventSubscription::SubscriptionCallback of a specific class instance.
	 */
    DWORD WINAPI CallbackWrapper(EVT_SUBSCRIBE_NOTIFY_ACTION Action, PVOID UserContext, EVT_HANDLE Event) {
        return reinterpret_cast<EventSubscription*>(UserContext)->SubscriptionCallback(Action, Event);
    }

    std::optional<std::wstring> EventLogs::GetEventParam(const EventWrapper& hEvent, const std::wstring& param) {
        auto queryParam = param.c_str();
        EventWrapper hContext = EvtCreateRenderContext(1, &queryParam, EvtRenderContextValues);
        if(!hContext) {
            LOG_ERROR(L"EventLogs::GetEventParam: EvtCreateRenderContext failed with " +
                      std::to_wstring(GetLastError()));
            return std::nullopt;
        }

        DWORD dwBufferSize{};
        if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, nullptr, &dwBufferSize, nullptr)) {
            if(ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
                auto pRenderedValues = AllocationWrapper{ HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize),
                                                          dwBufferSize, AllocationWrapper::HEAP_ALLOC };
                if(pRenderedValues) {
                    if(EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferSize,
                                 nullptr)) {
                        /*
						Table of variant members found here: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ns-winevt-evt_variant
						Table of type values found here: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_variant_type
						*/
                        PEVT_VARIANT result = reinterpret_cast<PEVT_VARIANT>((LPVOID) pRenderedValues);
                        if(result->Type == EvtVarTypeString)
                            return std::wstring(result->StringVal);
                        else if(result->Type == EvtVarTypeFileTime) {
                            wchar_t ar[30];
                            _ui64tow(result->FileTimeVal, ar, 10);
                            return ar;
                        } else if(result->Type == EvtVarTypeUInt16) {
                            return std::to_wstring(result->UInt16Val);
                        } else if(result->Type == EvtVarTypeUInt32) {
                            return std::to_wstring(result->UInt32Val);
                        } else if(result->Type == EvtVarTypeUInt64) {
                            return std::to_wstring(result->UInt64Val);
                        } else if(result->Type == EvtVarTypeNull)
                            return L"NULL";
                        else {
                            return L"Unknown VARIANT: " + std::to_wstring(result->Type);
                        }
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::optional<std::wstring> EventLogs::GetEventXML(const EventWrapper& hEvent) {
        DWORD dwBufferSize = 0;
        if(!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, nullptr, &dwBufferSize, nullptr)) {
            if(ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
                auto pRenderedContent = AllocationWrapper{ HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize),
                                                           dwBufferSize, AllocationWrapper::HEAP_ALLOC };
                if(pRenderedContent) {
                    if(EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferSize,
                                 nullptr)) {
                        return reinterpret_cast<LPCWSTR>((LPVOID) pRenderedContent);
                    }
                }
            }
        }

        return std::nullopt;
    }

    // Enumerate all the events in the result set.
    std::vector<EventLogItem> EventLogs::ProcessResults(const EventWrapper& hResults,
                                                        const std::vector<XpathQuery>& filters) {
        EVT_HANDLE hEvents[ARRAY_SIZE];

        std::vector<EventLogItem> results;
        std::vector<std::wstring> params;
        for(auto query : filters) {
            if(!query.SearchesByValue()) {
                params.push_back(query.ToString());
            }
        }

        DWORD dwReturned{};
        while(EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned)) {
            for(DWORD i = 0; i < dwReturned; i++) {
                auto item = EventToEventLogItem(hEvents[i], params);
                if(item) {
                    results.push_back(*item);
                }

                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
            }
        }

        for(unsigned i = 0; i < ARRAY_SIZE; i++) {
            if(hEvents[i]) {
                EvtClose(hEvents[i]);
            }
        }

        if(GetLastError() != ERROR_NO_MORE_ITEMS) {
            LOG_VERBOSE(1, "EventLogs::ProcessResults: EvtNext failed with " << GetLastError());
        }

        return results;
    }

    std::optional<EventLogItem> EventToEventLogItem(const EventWrapper& hEvent,
                                                    const std::vector<std::wstring>& params) {

        std::optional<std::wstring> eventIDStr, eventRecordIDStr, timeCreated, channel, rawXML;

        if(std::nullopt == (eventIDStr = GetEventParam(hEvent, L"Event/System/EventID")))
            return std::nullopt;
        if(std::nullopt == (eventRecordIDStr = GetEventParam(hEvent, L"Event/System/EventRecordID")))
            return std::nullopt;
        if(std::nullopt == (timeCreated = GetEventParam(hEvent, L"Event/System/TimeCreated/@SystemTime")))
            return std::nullopt;
        if(std::nullopt == (channel = GetEventParam(hEvent, L"Event/System/Channel")))
            return std::nullopt;
        if(std::nullopt == (rawXML = GetEventXML(hEvent)))
            return std::nullopt;

        EventLogItem pItem{};

        // Provide values for filtered parameters
        for(std::wstring key : params) {
            std::optional<std::wstring> val = GetEventParam(hEvent, key);
            if(!val) {
                return std::nullopt;
            }

            pItem.SetProperty(key, *val);
        }

        pItem.SetEventID(std::stoul(*eventIDStr));
        pItem.SetEventRecordID(std::stoul(*eventRecordIDStr));
        pItem.SetTimeCreated(*timeCreated);
        pItem.SetChannel(*channel);
        pItem.SetXML(*rawXML);

        return pItem;
    }

    std::vector<EventLogItem>
    EventLogs::QueryEvents(const std::wstring& channel, unsigned int id, const std::vector<XpathQuery>& filters) {
        std::vector<EventLogItem> items;

        auto query = std::wstring(L"Event/System[EventID=") + std::to_wstring(id) + std::wstring(L"]");
        for(auto param : filters)
            query += L" and " + param.ToString();

        EventWrapper hResults =
            EvtQuery(NULL, channel.c_str(), query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);
        if(!hResults) {
            if(ERROR_EVT_CHANNEL_NOT_FOUND == GetLastError())
                LOG_WARNING("EventLogs::QueryEvents: Unable to find channel " << channel);
            else if(ERROR_EVT_INVALID_QUERY == GetLastError())
                LOG_ERROR(L"EventLogs::QueryEvents: The query " << query << L" is not valid.");
            else
                LOG_ERROR("EventLogs::QueryEvents: EvtQuery failed with " << SYSTEM_ERROR);
        } else {
            items = ProcessResults(hResults, filters);
        }

        return items;
    }

    std::vector<EventSubscription> subscriptions = {};

    std::optional<std::reference_wrapper<EventSubscription>>
    EventLogs::SubscribeToEvent(const std::wstring& pwsPath,
                                unsigned int id,
                                const std::function<void(EventLogItem)>& callback,
                                const std::vector<XpathQuery>& filters) {
        auto query = std::wstring(L"Event/System[EventID=") + std::to_wstring(id) + std::wstring(L"]");
        for(auto param : filters)
            query += L" and " + param.ToString();

        subscriptions.emplace_back(EventSubscription{ callback });
        auto& eventSub = subscriptions[subscriptions.size() - 1];

        EventWrapper hSubscription = EvtSubscribe(NULL, NULL, pwsPath.c_str(), query.c_str(), NULL,
                                                  &subscriptions[subscriptions.size() - 1], CallbackWrapper,
                                                  EvtSubscribeToFutureEvents);
        eventSub.setSubHandle(hSubscription);

        if(!hSubscription) {
            if(ERROR_EVT_CHANNEL_NOT_FOUND == GetLastError())
                LOG_WARNING("EventLogs::QueryEvents: Unable to find channel " << pwsPath);
            else if(ERROR_EVT_INVALID_QUERY == GetLastError())
                LOG_ERROR(L"EventLogs::SubscribeToEvent: query " << query << L" is not valid.");
            else
                LOG_ERROR("EventLogs::SubscribeToEvent: EvtSubscribe failed with " << GetLastError());

            return std::nullopt;
        }

        return eventSub;
    }

    bool IsChannelOpen(const std::wstring& channel) {
        PEVT_VARIANT pProperty = NULL;
        PEVT_VARIANT pTemp = NULL;
        DWORD dwBufferSize = 0;
        DWORD dwBufferUsed = 0;

        // Open the channel config
        EventWrapper hChannel{ EvtOpenChannelConfig(NULL, channel.c_str(), 0) };
        if(NULL == hChannel) {
            LOG_ERROR(L"EventLogs::IsChannelOpen: EvtOpenChannelConfig failed with " + std::to_wstring(GetLastError()) +
                      L" for channel " + channel);
            return false;
        }

        // Attempt to get the channel property
        if(!EvtGetChannelConfigProperty(hChannel, EvtChannelConfigEnabled, 0, dwBufferSize, pProperty, &dwBufferUsed)) {
            auto status{ GetLastError() };
            if(ERROR_INSUFFICIENT_BUFFER == status) {
                dwBufferSize = dwBufferUsed;
                pTemp = (PEVT_VARIANT) realloc(pProperty, dwBufferSize);

                if(pTemp) {
                    pProperty = pTemp;
                    pTemp = NULL;
                    EvtGetChannelConfigProperty(hChannel, EvtChannelConfigEnabled, 0, dwBufferSize, pProperty,
                                                &dwBufferUsed);
                } else {
                    if(pProperty)
                        free(pProperty);

                    LOG_ERROR(L"EventLogs::IsChannelOpen: realloc failed for channel " + channel);
                    return false;
                }
            }

            if(ERROR_SUCCESS != (status = GetLastError())) {
                LOG_ERROR(L"EventLogs::IsChannelOpen: EvtGetChannelConfigProperty failed with " +
                          std::to_wstring(GetLastError()) + L" for channel " + channel);
                return false;
            }
        }
        if(pProperty)
            free(pProperty);

        return pProperty->BooleanVal;
    }

    bool OpenChannel(const std::wstring& channel) {
        EVT_HANDLE hChannel = NULL;
        EVT_VARIANT ChannelProperty;
        DWORD dwBufferSize = sizeof(EVT_VARIANT);
        hChannel = EvtOpenChannelConfig(NULL, channel.c_str(), 0);
        if(NULL == hChannel) {
            LOG_ERROR(L"EventLogs::OpenChannel: EvtOpenChannelConfig failed with " + std::to_wstring(GetLastError()) +
                      L" for channel " + channel);
            return false;
        }
        RtlZeroMemory(&ChannelProperty, dwBufferSize);

        ChannelProperty.Type = EvtVarTypeBoolean;
        ChannelProperty.BooleanVal = TRUE;

        if(!EvtSetChannelConfigProperty(hChannel, EvtChannelConfigEnabled, 0, &ChannelProperty)) {
            LOG_ERROR(L"EventLogs::OpenChannel: EvtSetChannelConfigProperty failed with " +
                      std::to_wstring(GetLastError()) + L" for channel " + channel);
            return false;
        }
        if(!EvtSaveChannelConfig(hChannel, 0)) {
            LOG_ERROR(L"EventLogs::OpenChannel: EvtSaveChannelConfig failed with " + std::to_wstring(GetLastError()) +
                      L" for channel " + channel);
            return false;
        }

        return true;
    }

}   // namespace EventLogs
