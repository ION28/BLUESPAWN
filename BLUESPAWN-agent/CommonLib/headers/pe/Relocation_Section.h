#pragma once

#include <Windows.h>

#include <vector>

#include "PE_Section.h"

class Relocation_Section : public PE_Section {
public:
	std::vector<Relocation_Block> vRelocationBlocks;

	Relocation_Section(const PE_Section& section);

	std::vector<DWORD> GetRelocRVAs();
};

struct Relocation_Block {
	DWORD rva;
	SIZE_T size;

	std::vector<Relocation_Entry> entries;

	Relocation_Block(MemoryWrapper<> location);

	std::vector<DWORD> GetRelocRVAs();
};

struct Relocation_Entry {
	WORD type : 3;
	WORD offset : 9;

	Relocation_Block block;

	DWORD GetRVA();
};