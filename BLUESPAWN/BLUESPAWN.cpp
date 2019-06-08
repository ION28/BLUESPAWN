#include "CollectInfo.h"
#include "Output.h"
#include "Registry.h"

using namespace std;


int main()
{
	OutputComputerInformation();
	cout << endl;
	ExamineRegistryPersistence();
	cout << endl;
	ExamineRegistryOtherBad();
	cout << endl;
	HuntT1101SecuritySupportProvider();
	HuntT1131AuthenticationPackage();
}

