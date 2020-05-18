

#include <string>
#include <vector>
#include <set>
#include <map>

#include "util/processes/ProcessUtils.h"
#include "util/filesystem/FileSystem.h"
#include "util/processes/CommandParser.h"
#include "util/log/Log.h"

std::vector<std::wstring> lolbins{
	L"cmd.exe",
	L"powershell.exe",
	L"explorer.exe",
	L"net.exe",
	L"net1.exe",
	L"At.exe",
	L"Atbroker.exe",
	L"Bash.exe",
	L"Bitsadmin.exe",
	L"Cmstp.exe",
	L"Diskshadow.exe",
	L"Dnscmd.exe",
	L"Extexport.exe",
	L"Forfiles.exe",
	L"Ftp.exe",
	L"Gpscript.exe",
	L"Hh.exe",
	L"Ie4uinit.exe",
	L"Ieexec.exe",
	L"Infdefaultinstall.exe",
	L"Installutil.exe",
	L"Mavinject.exe",
	L"Microsoft.Workflow.Compiler.exe",
	L"Mmc.exe",
	L"Msbuild.exe",
	L"Msconfig.exe",
	L"Msdt.exe",
	L"Mshta.exe",
	L"Msiexec.exe",
	L"Netsh.exe",
	L"Odbcconf.exe",
	L"Pcalua.exe",
	L"Pcwrun.exe",
	L"Presentationhost.exe",
	L"Rasautou.exe",
	L"Regasm.exe",
	L"Register-cimprovider.exe",
	L"Regsvcs.exe",
	L"Regsvr32.exe",
	L"Rundll32.exe",
	L"Runonce.exe",
	L"Runscripthelper.exe",
	L"Schtasks.exe",
	L"Scriptrunner.exe",
	L"SyncAppvPublishingServer.exe",
	L"Tttracer.exe",
	L"Verclsid.exe",
	L"Wab.exe",
	L"Wmic.exe",
	L"Xwizard.exe",
	L"Appvlp.exe",
	L"Bginfo.exe",
	L"Cdb.exe",
	L"csi.exe",
	L"Devtoolslauncher.exe",
	L"dnx.exe",
	L"Dotnet.exe",
	L"Dxcap.exe",
	L"Mftrace.exe",
	L"Msdeploy.exe",
	L"msxsl.exe",
	L"rcsi.exe",
	L"Sqlps.exe",
	L"SQLToolsPS.exe",
	L"Squirrel.exe",
	L"te.exe",
	L"Tracker.exe",
	L"Update.exe",
	L"vsjitdebugger.exe",
	L"Wsl.exe",
	L"Advpack.dll",
	L"Ieadvpack.dll",
	L"Ieaframe.dll",
	L"Mshtml.dll",
	L"Pcwutl.dll",
	L"Setupapi.dll",
	L"Shdocvw.dll",
	L"Shell32.dll",
	L"Syssetup.dll",
	L"Url.dll",
	L"Zipfldr.dll"
};

std::set<std::wstring> LolbinHashes{};

std::map<std::wstring, std::wstring> hashmap{};

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

bool IsLolbinMalicious(const std::wstring& command){
	std::wstring executable{ GetImagePathFromCommand(command) };
	
	if(!IsLolbin(executable)){
		return false;
	}

	auto args{ GetArgumentTokens(command) };
	auto hash{ FileSystem::File(executable).GetSHA256Hash() };
	if(hashmap.at(L"Rundll32.exe") == hash){
		if(args.size()){
			auto arg{ args[0] };
			auto dll{ arg.substr(0, arg.find_first_of(L" \t,")) };
			auto dllpath{ FileSystem::SearchPathExecutable(dll) };
			if(!dllpath || FileSystem::File(*dllpath).GetFileSigned()){
				LOG_INFO("rundll32 found to be executing " << dll);
				return true;
			} else if(IsLolbin(FileSystem::File(*dllpath))){
				LOG_INFO("rundll32 found to be executing " << dll);
				return true;
			}
		}
		return false;
	} else if(hashmap.at(L"explorer.exe") == hash){
		for(auto& arg : args){
			if(FileSystem::SearchPathExecutable(arg)){
				LOG_INFO("explorer found to be executing " << arg);
				return true;
			}
		}
		return false;
	} else return true;
}