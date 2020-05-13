#include "scan/ScanNode.h"

Association AddAssociation(Association a1, Association a2){
	Association combined[5][5] = {
		{ Association::Certain, Association::Certain, Association::Certain,  Association::Certain,  Association::Certain  },
		{ Association::Certain, Association::Certain, Association::Strong,   Association::Strong,   Association::Strong   },
		{ Association::Certain, Association::Strong,  Association::Strong,   Association::Moderate, Association::Moderate },
		{ Association::Certain, Association::Strong,  Association::Moderate, Association::Moderate, Association::Weak     },
		{ Association::Certain, Association::Strong,  Association::Moderate, Association::Weak,     Association::None     },
	};

	return combined[static_cast<DWORD>(a1)][static_cast<DWORD>(a2)];
}

Association MultiplyAssociation(Association a1, Association a2){
	Association combined[5][5] = {
		{ Association::Certain,  Association::Strong,   Association::Moderate, Association::Weak, Association::None },
		{ Association::Strong,   Association::Moderate, Association::Moderate, Association::Weak, Association::None },
		{ Association::Moderate, Association::Moderate, Association::Weak,     Association::Weak, Association::None },
		{ Association::Weak,     Association::Weak,     Association::Weak,     Association::None, Association::None },
		{ Association::None,     Association::None,     Association::None,     Association::None, Association::None },
	};

	return combined[static_cast<DWORD>(a1)][static_cast<DWORD>(a2)];
}

ScanNode::ScanNode(const Detection& detection) : 
	detection{ detection },
	certainty{ Certainty::None }{}

const std::map<ScanNode, Association>& ScanNode::GetAssociations() const {
	return associations;
}
