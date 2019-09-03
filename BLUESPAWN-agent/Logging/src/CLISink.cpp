#include <Windows.h>

#include <iostream>

#include "logging/CLISink.h"

namespace Log {

	void CLISink::SetConsoleColor(CLISink::MessageColor color){
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
	}

	void CLISink::LogMessage(LogLevel& level, std::string& message){
		if(level.Enabled()){
			SetConsoleColor(CLISink::PrependColors[static_cast<WORD>(level.severity)]);
			std::cout << CLISink::MessagePrepends[static_cast<WORD>(level.severity)] << " ";
			SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
			std::cout << message << std::endl;
		}
	}

	bool CLISink::operator==(LogSink& sink){
		return (bool) dynamic_cast<CLISink*>(&sink);
	}
}