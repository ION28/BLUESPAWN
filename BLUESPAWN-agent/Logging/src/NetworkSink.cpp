#include <Windows.h>

#include <iostream>

#include "logging/NetworkSink.h"

namespace Log {

	void NetworkSink::LogMessage(LogLevel& level, std::string& message) {
		if (level.Enabled()) {
			std::cout << "NetworkSink: ";
			std::cout << NetworkSink::MessagePrepends[static_cast<WORD>(level.severity)] << " ";
			std::cout << message << std::endl;
		}
	}

	void SendFileReaction(LogLevel& level, std::string& message) {
		if (level.Enabled()) {

		}
	}

	void SendRegistryReaction(LogLevel& level, std::string& message) {
		if (level.Enabled()) {

		}
	}

	void SendProcessReaction(LogLevel& level, std::string& message) {
		if (level.Enabled()) {

		}
	}

	void SendServiceReaction(LogLevel& level, std::string& message) {
		if (level.Enabled()) {

		}
	}

	bool NetworkSink::operator==(LogSink& sink) {
		return (bool) dynamic_cast<NetworkSink*>(&sink);
	}
}