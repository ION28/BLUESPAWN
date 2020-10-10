#include <Windows.h>

#include "hooking/Call.h"

BLUESPAWN::Agent::Call::Call(_In_ const Address& address, _In_ const std::vector<Address>& callStack, 
							 _In_ const std::vector<Argument>& arguments) : Address{ address }, callStack{ callStack },
	                                                                        arguments{ arguments }{}

BLUESPAWN::Agent::Call::Call(_In_ Address&& address, _In_ std::vector<Address>&& callStack, 
							 _In_ std::vector<Argument>&& arguments) : Address{ std::move(address) }, 
	                                                                   callStack{ std::move(callStack) }, 
	                                                                   arguments{ std::move(arguments) }{}