#pragma once

#include <iostream>

enum class SecurityLevel {
	Low,
	Medium,
	High
};


class Mitigation {

	public:
		// Query if the mitigation is currently enforced on the host system
		virtual bool isEnforced(SecurityLevel level);

		// Enforce the system. Return if sucesful or not
		virtual bool enforce(SecurityLevel level);
		
		std::string getName();
		std::string getDescription();

	protected:
		std::string name;
		std::string description;

};