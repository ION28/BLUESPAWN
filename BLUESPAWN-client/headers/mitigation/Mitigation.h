#pragma once

#include <iostream>

#include "util/reaction/Reaction.h"

enum class SecurityLevel {
	Low,
	Medium,
	High
};

class MitigationRegister;

class Mitigation {

	public:
		Mitigation(MitigationRegister& mr, const std::string& name);

		// Query if the mitigation is currently enforced on the host system
		virtual bool isEnforced(SecurityLevel level, Reaction reaction);

		// Enforce the system. Return if sucesful or not
		virtual bool enforce(SecurityLevel level, Reaction reaction);
		
		std::string getName();
		std::string getDescription();

	protected:
		std::string name;
		std::string description;

};