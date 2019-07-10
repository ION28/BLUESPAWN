#include "Hunt.h"

int Hunt::ScanCursory(Scope& scope){
	if(!(SupportedScans & Aggressiveness::Cursory)){
		return -1;
	}
	return 0;
}

int Hunt::ScanModerate(Scope& scope){
	if(!(SupportedScans & Aggressiveness::Moderate)){
		return -1;
	}
	return 0;
}

int Hunt::ScanCareful(Scope& scope){
	if(!(SupportedScans & Aggressiveness::Careful)){
		return -1;
	}
	return 0;
}

int Hunt::ScanAggressive(Scope& scope){
	if(!(SupportedScans & Aggressiveness::Aggressive)){
		return -1;
	}
	return 0;
}