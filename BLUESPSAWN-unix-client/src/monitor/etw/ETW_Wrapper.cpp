/*
#include "monitor/ETW_Wrapper.h"
#include <iostream>

ETW_Wrapper::ETW_Wrapper() : pshellProvider(etw_guid::powershell),
firewallProvider(etw_guid::firewall),
groupPolicyProvider(etw_guid::groupPolicy)
{
}

ETW_Wrapper::~ETW_Wrapper() {
	traceThread->join();
	delete traceThread;
}

void ETW_Wrapper::addPowershellCallback(const std::function <void(const EVENT_RECORD&)>& f) {
	pshellProvider.add_on_event_callback(f);
}

void ETW_Wrapper::addFirewallCallback(const std::function <void(const EVENT_RECORD&)>& f) {
	firewallProvider.add_on_event_callback(f);
}

void ETW_Wrapper::addGPCallback(const std::function <void(const EVENT_RECORD&)>& f) {
	groupPolicyProvider.add_on_event_callback(f);
}

void ETW_Wrapper::init() {
	// user_trace providers typically have any and all flags, whose meanings are
	// unique to the specific providers that are being invoked. To understand these
	// flags, you'll need to look to the ETW event producer.
	//pshellProvider.any(0xf0010000000003ff);

	traceThread = new std::thread(&ETW_Wrapper::startUserTrace, this);
}

void ETW_Wrapper::startUserTrace() {
	userTrace.enable(pshellProvider);
	userTrace.enable(firewallProvider);
	userTrace.enable(groupPolicyProvider);

	// begin listening for events. This call blocks, so if you want to do other things
	// while this runs, you'll need to call this on another thread.
	userTrace.start();
}
*/