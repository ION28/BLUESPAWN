#include "scan/Scanner.h"

std::unordered_map<std::reference_wrapper<Detection>, Association> Scanner::GetAssociatedDetections(
	IN CONST Detection& detection){
	return {};
}

bool Scanner::PerformQuickScan(IN CONST std::wstring& info){
	return false;
}

Certainty Scanner::ScanDetection(IN CONST Detection& detection){
	return Certainty::None;
}