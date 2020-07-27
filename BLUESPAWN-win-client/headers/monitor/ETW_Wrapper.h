#pragma once
/*

#include "krabs.hpp"
#include <thread>
*/

/*
Providers on a Windows machine can be found with
cmd: logman.exe query providers
or Powershell: Get-NetEventProvider -ShowInstalled | Select-Object Name,Guid | sort Name
*/
/*
namespace etw_guid {
	static krabs::guid powershell = krabs::guid(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
	static krabs::guid firewall = krabs::guid(L"{E595F735-B42A-494B-AFCD-B68666945CD3}");
	static krabs::guid groupPolicy = krabs::guid(L"{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}");
}

class ETW_Wrapper {
	public:
		ETW_Wrapper();
		~ETW_Wrapper();

		void init();
		void addPowershellCallback(const std::function <void(const EVENT_RECORD&)>& f);
		void addFirewallCallback(const std::function <void(const EVENT_RECORD&)>& f);
		void addGPCallback(const std::function <void(const EVENT_RECORD&)>& f);

	private:
		krabs::user_trace userTrace;

		krabs::provider<> pshellProvider;
		krabs::provider<> firewallProvider;
		krabs::provider<> groupPolicyProvider;

		std::thread * traceThread;
		void startUserTrace();
};
*/