#include "Reaction.h"

bool Reaction::SupportsReactions(DWORD dwDesired){
	return (dwDesired & dwSupportedReactions) == dwDesired;
}