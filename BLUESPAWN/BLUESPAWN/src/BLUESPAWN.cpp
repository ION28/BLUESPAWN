#include "Hunt.h"
#include "HuntT9999.h"
#include "HuntRegister.h"
#include "Output.h"

using namespace std;


int main(){
	HuntRegister record{};
	Hunts::HuntT9999 hTestHunt(record);

	hTestHunt.AddFileToSearch("C:\\Windows\\System32\\svchost.exe");
	hTestHunt.AddFileToSearch("C:\\Windows\\SysWOW64\\svchost.exe");

	// Sample scope to exclude SysWOW
	class LimitedScope : public Scope { 
	public: 
		LimitedScope() : Scope(){};
		virtual bool FileIsInScope(LPCSTR path){
			return !strstr(path, "SysWOW64");
		}
	};
	
	PrintInfoHeader("Running Hunt T9999 with an open scope.");
	Scope scope{};
	hTestHunt.ScanCursory(scope);

	PrintInfoHeader("Running Hunt T9999 with a limited scope.");
	LimitedScope limitedScope{};
	hTestHunt.ScanCursory(limitedScope);

}

