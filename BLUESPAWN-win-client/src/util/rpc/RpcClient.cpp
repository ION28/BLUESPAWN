#include "util/rpc/RpcClient.h"

#include <util/StringUtils.h>
#include <util/Utils.h>

namespace RpcClient {
    bool
    RpcClient::SendLogMessage(const std::wstring& msg, bluespawn::LogSeverity severity, bluespawn::LogDetail detail) {
        SYSTEMTIME st;
        GetSystemTime(&st);

        LogMessage request;
        request.set_clientid("TO_BE_SET_IN_THE_FUTURE");
        request.set_timestamp(SystemTimeToInteger(st));
        request.set_message(WidestringToString(msg));
        request.set_severity(severity);
        request.set_detail(detail);

        ResponseMessage response;
        ClientContext context;

        Status status = stub_->SendLogMessage(&context, request, &response);

        if(status.ok() && response.received()) {
            return true;
        } else {
            return false;
        }

        return false;
    }
}   // namespace RpcClient
