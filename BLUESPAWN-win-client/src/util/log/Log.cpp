#include "util/log/Log.h"

#include <iostream>

#include "util/StringUtils.h"

namespace Log {
    std::vector<std::shared_ptr<Log::LogSink>> _LogSinks;
    LogTerminator endlog{};

    LogMessage& LogMessage::operator<<(IN CONST LogTerminator& terminator) {
        auto message{ stream.str() };

        stream = std::wstringstream{};
        level.LogMessage(message);

        return *this;
    }

    LogMessage& LogMessage::InnerLog(IN CONST Loggable& loggable, IN CONST std::true_type&) {
        return operator<<(loggable.ToString());
    }

    template<>
    LogMessage& LogMessage::InnerLog(IN CONST LPCSTR& data, IN CONST std::false_type&) {
        stream << StringToWidestring(data);
        return *this;
    }

    template<>
    LogMessage& LogMessage::InnerLog(IN CONST std::string& data, IN CONST std::false_type&) {
        stream << StringToWidestring(data);
        return *this;
    }

    LogMessage::LogMessage(IN CONST LogLevel& level) : level{ level } {}
    LogMessage::LogMessage(IN CONST LogLevel& level, IN CONST std::wstringstream& message) : level{ level }, stream{} {
        stream << message.str();
    }

    void AddSink(IN CONST std::shared_ptr<LogSink>& sink,
                 IN CONST std::vector<std::reference_wrapper<LogLevel>>& levels) {
        LogSink* pointer{ sink.get() };
        bool exists{ false };

        for(auto& existing : _LogSinks) {
            if(*existing == *sink) {
                pointer = existing.get();
                exists = true;
            }
        }

        if(!exists) {
            _LogSinks.emplace_back(sink);
        }

        for(auto level : levels) {
            level.get().AddSink(pointer);
        }
    }

    std::wstring FormatErrorMessage(DWORD dwErrorCode) {
        //https://stackoverflow.com/a/45565001/3302799
        LPWSTR psz{ nullptr };
        auto cchMsg = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, nullptr,
            dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPTSTR>(&psz), 0, nullptr);
        if(cchMsg) {
            auto delfunc{ [](void* p) { ::LocalFree(p); } };
            std::unique_ptr<WCHAR, decltype(delfunc)> ptrBuffer(psz, delfunc);
            return std::wstring(ptrBuffer.get(), cchMsg);
        } else {
            auto error_code{ ::GetLastError() };
            return L"Unable to format error message!";
        }
    }
}   // namespace Log
