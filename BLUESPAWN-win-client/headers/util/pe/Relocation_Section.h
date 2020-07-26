#pragma once

#include <Windows.h>

#include <vector>

#include "util/pe/PE_Section.h"
#include "util/wrappers.hpp"

struct Relocation_Block;

struct RelocBlock {
	DWORD dwRelocationOffset;
	DWORD dwBlockSize;
};
struct RelocEntry {
	WORD type : 3;
	WORD offset : 9;
};

struct Relocation_Entry {
	WORD type : 3;
	WORD offset : 9;

	const Relocation_Block& block;

	DWORD GetRVA();

	Relocation_Entry(RelocEntry entry, const Relocation_Block& block);
};

struct Relocation_Block {
	DWORD rva;
	DWORD size;

	std::vector<Relocation_Entry> entries;

	Relocation_Block(DWORD rva, DWORD size, MemoryWrapper<RelocEntry> location);

	std::vector<DWORD> GetRelocRVAs();
};

class Relocation_Section : public PE_Section {
public:
	std::vector<Relocation_Block> vRelocationBlocks;

	Relocation_Section(const PE_Section& section);

	std::vector<DWORD> GetRelocRVAs();
};