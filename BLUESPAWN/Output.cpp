#include "Output.h"

void SetConsoleColor(string color) {
	//color documentation: https://stackoverflow.com/a/4053879/3302799
	/*
	10 - green
	11 - cyan
	12 - red
	14 - yellow
	15 - white
	*/
	int set_color;
	if (color == "green") {
		set_color = 10;
	}
	else if (color == "cyan") {
		set_color = 11;
	}
	else if (color == "red") {
		set_color = 12;
	}
	else if (color == "yellow") {
		set_color = 14;
	}
	else {
		set_color = 15;
	}
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, set_color);
}

void PrintInfoHeader(string out) {
	SetConsoleColor("yellow");
	cout << "[+] ";
	SetConsoleColor("white");
	cout << out << endl;
}

void PrintInfoStatus(string out) {
	SetConsoleColor("cyan");
	cout << "[*] ";
	SetConsoleColor("white");
	cout << out << endl;
}