#include "Hunt.h"
#include "HuntT9999.h"
#include "HuntRegister.h"

using namespace std;


int main(){
	HuntRegister record;
	Hunts::HuntT9999 hTestHunt(record);

	hTestHunt.AddFileToSearch("C:\\Windows\\System32\\svchost.exe");
	hTestHunt.AddFileToSearch("C:\\Windows\\System32\\svchost1.exe");

	Scope s{};
	hTestHunt.ScanCursory(s);
}

