#pragma once

#include "scan/Scanner.h"

class ProcessScanner : public Scanner {
public:
	virtual std::vector<std::shared_ptr<DETECTION>> GetAssociatedDetections(std::shared_ptr<DETECTION> base, Aggressiveness level);
};