#pragma once
#include "PE_Section.h"

#include <string>
#include <vector>

#include "common/wrappers.hpp"

class PE_Resource {
public:
	MemoryWrapper<> resource;
	std::wstring name;
	DWORD id;
};

class Resource_Section : public PE_Section {
public:
	std::vector<PE_Resource> resources;

	Resource_Section(const PE_Section& section);
};

