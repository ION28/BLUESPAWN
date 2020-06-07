

#include <string>
#include <vector>
#include <set>
#include <map>

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

//TODO: fill
std::vector<std::string> lolbins{
};

std::set<std::string> LolbinHashes{};

std::map<std::string, std::string> hashmap{};

bool IsLolbin(const FileSystem::File& file){
	if(!file.GetFileExists()){
		return false;
	}

	if(!LolbinHashes.size()){
		for(auto name : lolbins){
			auto path{ FileSystem::SearchPathExecutable(name) };
			if(path){
				auto hash{ FileSystem::File{ *path }.GetSHA256Hash() };
				if(hash){
					LolbinHashes.emplace(*hash);
					hashmap.emplace(name, *hash);
				}
			}
		}
	}

	auto hash{ file.GetSHA256Hash() };
	if(hash && LolbinHashes.count(*hash)){
		return true;
	}

	return false;
}

bool IsLolbinMalicious(const std::string& command){
	/*std::string executable{ GetImagePathFromCommand(command) };

	LOG_VERBOSE(1, "Checking if " << command << " will execute a lolbin maliciously");
	
	if(!IsLolbin(executable)){
		return false;
	}

	auto args{ GetArgumentTokens(command) };

	LOG_VERBOSE(3, "Getting hash of " << executable);
	auto hash{ FileSystem::File(executable).GetSHA256Hash() };

	LOG_VERBOSE(3, "Checking if " << executable << " is rundll32");
	if(hashmap.count("Rundll32.exe") && hashmap.at("Rundll32.exe") == hash){
		if(args.size()){
			auto arg{ args[0] };
			auto br{ arg.find_first_of(" \t,") };
			auto dll{ arg.substr(0, br) };
			auto dllpath{ FileSystem::SearchPathExecutable(dll) };

			FileSystem::File dllfile{ *dllpath };
			if(!dllpath || !dllfile.GetFileSigned()){
				LOG_INFO("rundll32 found to be executing " << dll);
				return true;
			} 
			
			if(hashmap.count("Shell32.dll") && hashmap.at("Shell32.dll") == dllfile.GetSHA256Hash() && br != std::string::npos){
				auto start{ arg.find_first_not_of(" ,\t", br) };
				auto func{ arg.substr(start, arg.find_first_of(" ,\t", start)) };
				LOG_INFO("rundll32 found to be executing shell32");
				return !CompareIgnoreCaseW(func, "SHCreateLocalServerRunDll");
			} else{
				LOG_INFO("rundll32 found to be executing " << dll);
				return true;
			}
		}
		return false;
	}

	LOG_VERBOSE(3, "Checking if " << executable << " is mmc.exe");
	if(hashmap.count("Mmc.exe") && hashmap.at("Mmc.exe") == hash){
		for(auto& arg : args){
			if(FileSystem::SearchPathExecutable(arg)){
				LOG_INFO("mmc found to be executing " << arg);
				return true;
			}
		}
		return false;
	}

	LOG_VERBOSE(3, "Checking if " << executable << " is presentationhost");
	if(hashmap.count("Presentationhost.exe") && hashmap.at("Presentationhost.exe") == hash){
		for(auto& arg : args){
			if(FileSystem::SearchPathExecutable(arg)){
				LOG_INFO("mmc found to be executing " << arg);
				return true;
			}
		}
		return false;
	}

	LOG_VERBOSE(3, "Checking if " << executable << " is Mshta.exe");
	if(hashmap.count("Mshta.exe") && hashmap.at("Mshta.exe") == hash){
		return args.size();
	}

	LOG_VERBOSE(3, "Checking if " << executable << " is explorer.exe");
	if(hashmap.count("explorer.exe") && hashmap.at("explorer.exe") == hash){
		for(auto& arg : args){
			if(FileSystem::SearchPathExecutable(arg)){
				LOG_INFO("explorer found to be executing " << arg);
				return true;
			}
		}
		return false;
	} else return true;*/

	return true;
}