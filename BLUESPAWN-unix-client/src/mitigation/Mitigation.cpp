#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "reaction/Reaction.h"

Mitigation::Mitigation(const std::string& name, const std::string& description, const std::string& software,
	SoftwareAffected category, MitigationSeverity severity) :
	name{ name },
	description{ description },
	software{ software },
	category{ category },
	severity{ severity } {
}

std::string Mitigation::getName() {
	return this->name;
}

std::string Mitigation::getDescription() {
	return this->description;
}