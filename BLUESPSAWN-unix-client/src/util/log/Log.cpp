#include "util/log/Log.h"
#include <iostream>

namespace Log {
	std::vector<std::shared_ptr<Log::LogSink>> _LogCurrentSinks; 
	LogTerminator endlog{};

	LogMessage& LogMessage::operator<<(const std::wstring& message){
		LPCWSTR lpwMessage = message.c_str();
		LPSTR lpMessage = new CHAR[message.length() + 1]{};
		WideCharToMultiByte(CP_ACP, 0, lpwMessage, static_cast<int>(message.length()), lpMessage, static_cast<int>(message.length()), 0, nullptr);

		InternalStream << std::string(lpMessage);
		return *this;
	}
	LogMessage& LogMessage::operator<<(PCWSTR pointer){
		return operator<<(std::wstring(pointer));
	}
	LogMessage& LogMessage::operator<<(const LogTerminator& terminator){
		std::string message = InternalStream.str();

		InternalStream = std::stringstream();
		for(int idx = 0; idx < Sinks.size(); idx++){
			Sinks[idx]->LogMessage(Level, message);
		}
		return *this;
	}

	LogMessage::LogMessage(const std::shared_ptr<LogSink>& Sink, LogLevel Level) : Level{ Level } {
		Sinks.emplace_back(Sink);
	}
	LogMessage::LogMessage(std::vector<std::shared_ptr<LogSink>> Sinks, LogLevel Level) : LogMessage(Sinks, Level, std::stringstream{}) {}
	LogMessage::LogMessage(std::vector<std::shared_ptr<LogSink>> Sinks, LogLevel Level, std::stringstream Stream) : Level{ Level } {
		this->Sinks = Sinks;
		std::string StreamContents = Stream.str();
		InternalStream << StreamContents;
	}

	bool AddSink(const std::shared_ptr<LogSink>& Sink){
		for(int idx = 0; idx < _LogCurrentSinks.size(); idx++){
			if(*_LogCurrentSinks[idx] == *Sink){
				return false;
			}
		}

		_LogCurrentSinks.emplace_back(Sink);
		return true;
	}

	bool RemoveSink(const std::shared_ptr<LogSink>& Sink){
		for(int idx = 0; idx < _LogCurrentSinks.size(); idx++){
			if(*_LogCurrentSinks[idx] == *Sink){
				_LogCurrentSinks.erase(_LogCurrentSinks.begin() + idx);
				return true;
			}
		}

		return false;
	}

	std::wstring FormatErrorMessage(DWORD dwErrorCode) {
		//https://stackoverflow.com/a/45565001/3302799
		LPWSTR psz{ nullptr };
		auto cchMsg = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM
			| FORMAT_MESSAGE_IGNORE_INSERTS
			| FORMAT_MESSAGE_ALLOCATE_BUFFER,
			nullptr,
			dwErrorCode,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			reinterpret_cast<LPTSTR>(&psz),
			0,
			nullptr);
		if (cchMsg) {
			auto delfunc{ [](void* p) { ::LocalFree(p); } };
			std::unique_ptr<WCHAR, decltype(delfunc)> ptrBuffer(psz, delfunc);
			return std::wstring(ptrBuffer.get(), cchMsg);
		}
		else {
			auto error_code{ ::GetLastError() };
			return L"Unable to format error message!";
		}
	}
}
