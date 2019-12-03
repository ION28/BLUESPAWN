#include "mitigations/Mitigation.h"

std::string Mitigation::getName() {
	return this->name;
}

std::string Mitigation::getDescription() {
	return this->description();
}