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

	void NetworkSink::SendFileReaction(LogLevel& level, std::string& message) {
		if (level.Enabled()) {

		}
	}

	void NetworkSink::SendRegistryReaction(LogLevel& level, std::string& message) {
		if (level.Enabled()) {

		}
	}

	void NetworkSink::SendProcessReaction(LogLevel& level, std::string& message) {
		if (level.Enabled()) {

		}
	}

	void NetworkSink::SendServiceReaction(LogLevel& level, std::string& message) {
		if (level.Enabled()) {

		}
	}

	bool NetworkSink::operator==(LogSink& sink) {
		return (bool) dynamic_cast<NetworkSink*>(&sink);
	}
}