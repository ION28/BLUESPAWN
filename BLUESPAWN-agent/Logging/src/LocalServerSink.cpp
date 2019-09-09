#include <Windows.h>

#include <iostream>

#include "logging/LocalServerSink.h"

namespace Log {
	
	// Logs string message to server prepended by the security level
	void LocalServerSink::LogMessage(LogLevel& level, std::string& message) {
		std::cout << LocalServerSink::MessagePrepends[static_cast<WORD>(level.severity)] << " ";
		std::cout << message << std::endl;
	}

	void LocalServerSink::LogFileReaction(LogLevel& level, FILE_DETECTION* fileData, std::string& message) {

	}

	void LocalServerSink::LogRegistryReaction(LogLevel& level, REGISTRY_DETECTION* registryData, std::string& message) {

	}

	void LocalServerSink::LogProcessReaction(LogLevel& level, SERVICE_DETECTION* serviceData, std::string& message) {

	}

	void LocalServerSink::LogServiceReaction(LogLevel& level, PROCESS_DETECTION* processData, std::string& message) {

	}

	void LocalServerSink::StartHunt(std::string& huntName) {
		if (!this->hunting) {
			this->hunting = true;
			this->huntName = huntName;
		} else {
			// TODO: handle starting a hunt when one isn't ended
		}
	}

	void LocalServerSink::EndHunt() {
		if (this->hunting) {
			this->hunting = false;
		}
	}

	bool LocalServerSink::operator==(LogSink& sink) {
		return (bool) dynamic_cast<LocalServerSink*>(&sink);
	}
}