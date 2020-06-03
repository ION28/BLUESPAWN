#pragma once

#include <iostream>

enum class SecurityLevel {
	Low,
	Medium,
	High
};

enum class MitigationMode {
	Audit,
	Enforce
};

enum class MitigationSeverity {
	Low,     // Corresponds to a CVSS score of <= 4 or a low severity item on a STIG
	Medium,  // Corresponds to a CVSS score of <= 7 or a medium severity item on a STIG
	High     // Corresponds to a CVSS score of > 7 or a high severity item on a STIG
};

enum class SoftwareAffected {
	OperatingSystem,
	UserInformation,
	DomainAdministration,
	InternalService,
	ExposedService
};

class MitigationRegister;

class Mitigation {

public:
	Mitigation(const std::string& name, const std::string& description, const std::string& software, 
		SoftwareAffected category, MitigationSeverity severity);

	// Query if the mitigation is currently enforced on the host system
	virtual bool MitigationIsEnforced(SecurityLevel level) = 0;

	// Enforce the system. Return if sucesful or not
	virtual bool EnforceMitigation(SecurityLevel level) = 0;

	virtual bool MitigationApplies() = 0;

	std::string getName();
	std::string getDescription();

protected:
	std::string name;
	std::string description;
	std::string software;

	SoftwareAffected category;
	MitigationSeverity severity;
};