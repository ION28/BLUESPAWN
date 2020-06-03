#include "util/processes/ProcessUtils.h"
#include "util/processes/CommandParser.h"

#include <string>

#include "common/StringUtils.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

std::string GetImagePathFromCommand(std::string wsCmd){
    if(wsCmd.substr(0, 11) == "\\SystemRoot"){
        wsCmd = "%SYSTEMROOT%" + wsCmd.substr(11);
    }

    wsCmd = ExpandEnvStringsW(wsCmd);

    auto start = wsCmd.find_first_not_of(" \f\v\t\n\r", 0);
    if(wsCmd.size() >= 4 && wsCmd.substr(start, 4) == "\\??\\"){
        start += 4;
    }
    if(start == std::string::npos){
        return "";
    } else if(wsCmd.at(start) == '"' || wsCmd.at(start) == '\''){
        auto name = wsCmd.substr(start + 1, wsCmd.find_first_of("'\"", start + 1) - start - 1);
        auto path = FileSystem::SearchPathExecutable(name);
        if(path){
            return *path;
        } else return name;
    } else{
        auto idx = start;
        while(idx != std::string::npos){
            auto spacepos = wsCmd.find(" ", idx);
            auto name = wsCmd.substr(start, spacepos - start);
            auto path = FileSystem::SearchPathExecutable(name);
            if(path && FileSystem::CheckFileExists(*path)){
                return *path;
            }

            if(name.length() > 4 && CompareIgnoreCaseW(name.substr(name.length() - 4), ".exe")){
                return name;
            }

            if(spacepos == std::string::npos){
                return name;
            }

            idx = spacepos + 1;
        }

        return wsCmd.substr(start, wsCmd.find_first_of(" \t\n\r", start) - start);
    }
}

std::vector<std::string> TokenizeCommand(const std::string& command){
    std::vector<std::string> tokens{};

    std::vector<std::string> words{ SplitStringW(command, " ") };

    std::string quoted{};

    bool inquotes = false;
    bool singlequotes = false;
    for(auto& str : words){
        if(inquotes){
            if(str.length() && ((!singlequotes && str.find_last_of("\"") == str.length() - 1) ||
                                (singlequotes && str.find_last_of("'") == str.length() - 1))){
                inquotes = false;
                quoted += " " + str.substr(0, str.length() - 1);
                for(size_t idx = 0; idx < str.length() - 1; idx++){
                    if(!singlequotes && str.at(idx) == '\\' && str.at(idx + 1) == '"'){
                        str.replace(str.begin() + idx, str.begin() + idx + 2, "\"");
                    }
                    if(singlequotes && str.at(idx) == '\\' && str.at(idx + 1) == '\''){
                        str.replace(str.begin() + idx, str.begin() + idx + 2, "'");
                    }
                }
                tokens.emplace_back(quoted);
            } else{
                quoted += " " + str;
            }
        } else{
            if(str.at(0) == '"' || str.at(0) == '\''){
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

std::vector<std::string> GetArgumentTokens(const std::string& command){
    LOG_VERBOSE(2, "Finding arguments for command " << command);

    std::string executable{};
    auto start = command.find_first_not_of(" \f\v\t\n\r", 0);

    if(command.substr(start, 4) == "\\??\\"){
        start += 4;
    }
    if(start == std::string::npos){
        return {};
    } else if(command.at(start) == '"' || command.at(start) == '\''){
        auto end{ command.find_first_of("'\"", start + 1) - start - 1 };
        start = command.find_first_not_of(" \f\v\t\n\r", end);
        
        LOG_VERBOSE(3, "Command is quoted; rest begins at " << start);
        return TokenizeCommand(command.substr(start));
    }

    LOG_VERBOSE(3, "Command is not quoted; searching for executable");
    auto tokens{ TokenizeCommand(command.substr(start)) };
    LOG_VERBOSE(3, "Successfully tokenized command");
    for(size_t idx = 0; idx < tokens.size(); idx++){
        if(!executable.length()){
            executable += tokens[idx];
        } else executable += " " + tokens[idx];

        LOG_VERBOSE(3, "Trying " << executable);
        auto path = FileSystem::SearchPathExecutable(executable);
        if(path){
            return std::vector<std::string>(tokens.begin() + idx + 1, tokens.end());
        }
    }

    return {};
}