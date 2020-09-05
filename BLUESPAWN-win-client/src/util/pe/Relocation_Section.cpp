#include "util/pe/Relocation_Section.h"

#include <Windows.h>

#include "util/pe/PE_Section.h"

Relocation_Entry::Relocation_Entry(RelocEntry entry, const Relocation_Block& block) : block{ block }{
	this->type = entry.type;
	this->offset = entry.offset;
}

DWORD Relocation_Entry::GetRVA(){
	// TODO: Add more than the trivial case!
	if(type != 0){
		return block.rva + offset;
	} else return 0;
}

Relocation_Block::Relocation_Block(DWORD offset, DWORD size, MemoryWrapper<RelocEntry> memory){
	for(unsigned int i = 0; i < size; i += sizeof(RelocEntry)){
		entries.emplace_back(memory.GetOffset(i).Dereference(), *this);
	}
}

std::vector<DWORD> Relocation_Block::GetRelocRVAs(){
	std::vector<DWORD> RVAs = {};
	for(auto entry : entries){
		if(entry.type != 0){
			RVAs.emplace_back(entry.GetRVA());
		}
	}
	return RVAs;
}

Relocation_Section::Relocation_Section(const PE_Section& section) : PE_Section(section) {
	RelocBlock BlockInfo = { 1, 1 };
	for(DWORD offset = 0; offset < section.SectionHeader.SizeOfRawData && BlockInfo.dwBlockSize != 0 && BlockInfo.dwRelocationOffset != 0; offset += BlockInfo.dwBlockSize){
		BlockInfo = *section.SectionContent.GetOffset(offset).Convert<RelocBlock>();
		Relocation_Block block = { BlockInfo.dwRelocationOffset, BlockInfo.dwBlockSize, section.SectionContent.GetOffset(offset + 8).Convert<RelocEntry>() };
		vRelocationBlocks.emplace_back(block);
	}
};

std::vector<DWORD> Relocation_Section::GetRelocRVAs(){
	std::vector<DWORD> RVAs = {};
	for(auto block : vRelocationBlocks){
		for(auto entry : block.GetRelocRVAs()){
			RVAs.emplace_back(entry);
		}
	}

	return RVAs;
}