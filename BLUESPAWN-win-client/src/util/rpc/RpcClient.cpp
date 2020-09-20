#include "util/rpc/RpcClient.h"

#include <util/StringUtils.h>
#include <util/Utils.h>

namespace RpcClient {
    bool RpcClient::SendLogMessage(const std::wstring& msg,
                                   bluespawn::LogMessageRequest_Severity severity,
                                   bluespawn::LogMessageRequest_Detail detail) {
        SYSTEMTIME st;
        GetSystemTime(&st);

        LogMessageRequest request;
        request.set_client_id("TO_BE_SET_IN_THE_FUTURE");
        request.set_timestamp(SystemTimeToInteger(st));
        request.set_message(WidestringToString(msg));
        request.set_severity(severity);
        request.set_detail(detail);

        LogMessageResponse response;
        ClientContext context;

        Status status = stub_->SendLog(&context, request, &response);

        if(status.ok() && response.received()) {
            return true;
        } else {
            return false;
        }

        return false;
    }
}   // namespace RpcClient
