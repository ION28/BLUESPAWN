#include <Windows.h>

#include "hooking/Call.h"

BLUESPAWN::Agent::Call::Call(_In_ const std::vector<Address>& callStack, _In_ const std::vector<Argument>& arguments) :
	callStack{ callStack }, arguments{ arguments }{}

BLUESPAWN::Agent::Call::Call(_In_ std::vector<Address>&& callStack, _In_ std::vector<Argument>&& arguments) :
	callStack{ std::move(callStack) }, arguments{ std::move(arguments) }{}