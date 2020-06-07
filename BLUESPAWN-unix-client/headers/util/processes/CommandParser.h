#pragma once

#include <vector>
#include <string>

std::vector<std::string> TokenizeCommand(const std::string& command);
std::vector<std::string> GetArgumentTokens(const std::string& command);