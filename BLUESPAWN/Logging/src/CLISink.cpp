#include <Windows.h>

#include <iostream>

#include "logging/CLISink.h"

namespace Log {
	void CLISink::SetMode(Mode mode){
		this->CurrentMode = mode;
	}

	void CLISink::SetConsoleColor(CLISink::MessageColor color){
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
	}

	void CLISink::LogMessage(std::string& message){
		SetConsoleColor(CLISink::PrependColors[static_cast<WORD>(CurrentMode)]);
		std::cout << CLISink::MessagePrepends[static_cast<WORD>(CurrentMode)] << " ";
		SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
		std::cout << message << std::endl;
	}

	bool CLISink::operator==(LogSink& sink){
		return (bool) dynamic_cast<CLISink*>(&sink);
	}
}