#include "CollectInfo.h"
#include "Output.h"
#include "Registry.h"

using namespace std;


int main()
{
	PrintInfoHeader("Computer Information");
	PrintInfoStatus("DNS FQDN: " + GetFQDN());
	PrintInfoStatus("Computer DNS Name: " + GetComputerDNSName());
	PrintInfoStatus("Active Directory Domain: " + GetDomain());
	PrintInfoStatus("Operating System: " + GetOsVersion());
	PrintInfoStatus("Current User: " + GetCurrentUser());
}

