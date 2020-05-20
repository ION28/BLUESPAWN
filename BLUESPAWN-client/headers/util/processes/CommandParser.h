#pragma once

#include <vector>
#include <string>

std::vector<std::wstring> TokenizeCommand(const std::wstring& command);
std::vector<std::wstring> GetArgumentTokens(const std::wstring& command);