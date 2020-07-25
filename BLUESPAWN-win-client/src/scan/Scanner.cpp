#include "scan/Scanner.h"

#include "scan/FileScanner.h"
#include "scan/MemoryScanner.h"
#include "scan/ProcessScanner.h"
#include "scan/RegistryScanner.h"

std::vector<std::shared_ptr<Scanner>> Scanner::scanners{
    std::make_shared<FileScanner>(),
    std::make_shared<MemoryScanner>(),
    std::make_shared<ProcessScanner>(),
    std::make_shared<RegistryScanner>(),
};

std::unordered_map<std::shared_ptr<Detection>, Association>
Scanner::GetAssociatedDetections(IN CONST Detection& detection) {
    return {};
}

Certainty Scanner::ScanDetection(IN CONST Detection& detection) {
    return Certainty::None;
}
