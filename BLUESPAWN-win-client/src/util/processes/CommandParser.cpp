#include "util/processes/ProcessUtils.h"
#include "util/processes/CommandParser.h"

#include <string>

#include "util/StringUtils.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

std::wstring GetImagePathFromCommand(std::wstring wsCmd){
    if(wsCmd.substr(0, 11) == L"\\SystemRoot"){
        wsCmd = L"%SYSTEMROOT%" + wsCmd.substr(11);
    }

    wsCmd = ExpandEnvStringsW(wsCmd);

    auto start = wsCmd.find_first_not_of(L" \f\v\t\n\r", 0);
    if(wsCmd.size() >= 4 && wsCmd.substr(start, 4) == L"\\??\\"){
        start += 4;
    }
    if(start == std::wstring::npos){
        return L"";
    } else if(wsCmd.at(start) == '"' || wsCmd.at(start) == '\''){
        auto name = wsCmd.substr(start + 1, wsCmd.find_first_of(L"'\"", start + 1) - start - 1);
        auto path = FileSystem::SearchPathExecutable(name);
        if(path){
            return *path;
        } else return name;
    } else{
        auto idx = start;
        while(idx != std::wstring::npos){
            auto spacepos = wsCmd.find(L" ", idx);
            auto name = wsCmd.substr(start, spacepos - start);
            auto path = FileSystem::SearchPathExecutable(name);
            if(path && FileSystem::CheckFileExists(*path)){
                return *path;
            }

            if(name.length() > 4 && CompareIgnoreCaseW(name.substr(name.length() - 4), L".exe")){
                return name;
            }

            if(spacepos == std::wstring::npos){
                return name;
            }

            idx = spacepos + 1;
        }

        return wsCmd.substr(start, wsCmd.find_first_of(L" \t\n\r", start) - start);
    }
}

std::vector<std::wstring> TokenizeCommand(const std::wstring& command){
    std::vector<std::wstring> tokens{};

    std::vector<std::wstring> words{ SplitStringW(command, L" ") };

    std::wstring quoted{};

    bool inquotes = false;
    bool singlequotes = false;
    for(auto& str : words){
        if(inquotes){
            if(str.length() && ((!singlequotes && str.find_last_of(L"\"") == str.length() - 1) ||
                                (singlequotes && str.find_last_of(L"'") == str.length() - 1))){
                inquotes = false;
                quoted += L" " + str.substr(0, str.length() - 1);
                for(size_t idx = 0; idx < str.length() - 1; idx++){
                    if(!singlequotes && str.at(idx) == L'\\' && str.at(idx + 1) == L'"'){
                        str.replace(str.begin() + idx, str.begin() + idx + 2, L"\"");
                    }
                    if(singlequotes && str.at(idx) == L'\\' && str.at(idx + 1) == L'\''){
                        str.replace(str.begin() + idx, str.begin() + idx + 2, L"'");
                    }
                }
                tokens.emplace_back(quoted);
            } else{
                quoted += L" " + str;
            }
        } else{
            if(str.at(0) == L'"' || str.at(0) == '\''){
                quoted = str.substr(1);
                inquotes = true;
                singlequotes = str.at(0) == '\'';
            } else{
                tokens.emplace_back(str);
            }
        }
    }

    if(inquotes){
        tokens.emplace_back(quoted);
    }

    return tokens;
}

std::vector<std::wstring> GetArgumentTokens(const std::wstring& command){
    LOG_VERBOSE(2, "Finding arguments for command " << command);

    std::wstring executable{};
    auto start = command.find_first_not_of(L" \f\v\t\n\r", 0);

    if(command.substr(start, 4) == L"\\??\\"){
        start += 4;
    }
    if(start == std::wstring::npos){
        return {};
    } else if(command.at(start) == '"' || command.at(start) == '\''){
        auto end{ command.find_first_of(L"'\"", start + 1) - start - 1 };
        start = command.find_first_not_of(L" \f\v\t\n\r", end);
        
        LOG_VERBOSE(3, "Command is quoted; rest begins at " << start);
        return TokenizeCommand(command.substr(start));
    }

    LOG_VERBOSE(3, "Command is not quoted; searching for executable");
    auto tokens{ TokenizeCommand(command.substr(start)) };
    LOG_VERBOSE(3, "Successfully tokenized command");
    for(size_t idx = 0; idx < tokens.size(); idx++){
        if(!executable.length()){
            executable += tokens[idx];
        } else executable += L" " + tokens[idx];

        LOG_VERBOSE(3, "Trying " << executable);
        auto path = FileSystem::SearchPathExecutable(executable);
        if(path){
            return std::vector<std::wstring>(tokens.begin() + idx + 1, tokens.end());
        }
    }

    return {};
}