#include <Windows.h>

#include <iostream>

int main(int argc, char** argv){
	if(argc != 2){
		return -1;
	} else{
		auto funcName{ argv[1] };

		auto lib{ LoadLibraryW(L".\\BLUESPAWN-win-agent.dll") };
		if(lib){
			auto func = GetProcAddress(lib, funcName);
			((void(*)()) func)();
		} else{
			std::cerr << "Unable to load BLUESPAWN-win-agent.dll" << std::endl;
		}
	}
}