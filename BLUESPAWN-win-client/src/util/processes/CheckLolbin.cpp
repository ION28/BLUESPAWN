

#include <map>
#include <set>
#include <string>
#include <vector>

#include "util/StringUtils.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/processes/CommandParser.h"
#include "util/processes/ProcessUtils.h"

std::vector<std::wstring> lolbins{ L"cmd.exe",
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
                                   L"Zipfldr.dll" };

std::set<std::wstring> LolbinHashes{};

std::map<std::wstring, std::wstring> hashmap{};

bool IsLolbin(const FileSystem::File& file) {
    if(!file.GetFileExists()) {
        return false;
    }

    if(!LolbinHashes.size()) {
        for(auto name : lolbins) {
            auto path{ FileSystem::SearchPathExecutable(name) };
            if(path) {
                auto hash{ FileSystem::File{ *path }.GetSHA256Hash() };
                if(hash) {
                    LolbinHashes.emplace(*hash);
                    hashmap.emplace(name, *hash);
                }
            }
        }
    }

    auto hash{ file.GetSHA256Hash() };
    if(hash && LolbinHashes.count(*hash)) {
        return true;
    }

    return false;
}

bool IsLolbinMalicious(const std::wstring& command) {
    std::wstring executable{ GetImagePathFromCommand(command) };

    LOG_VERBOSE(1, "Checking if " << command << " will execute a lolbin maliciously");

    if(!IsLolbin(executable)) {
        return false;
    }

    auto args{ GetArgumentTokens(command) };

    LOG_VERBOSE(3, "Getting hash of " << executable);
    auto hash{ FileSystem::File(executable).GetSHA256Hash() };

    LOG_VERBOSE(3, "Checking if " << executable << " is rundll32");
    if(hashmap.count(L"Rundll32.exe") && hashmap.at(L"Rundll32.exe") == hash) {
        if(args.size() && args[0] != L"/sta") {
            auto arg{ args[0] };
            auto br{ arg.find_first_of(L" \t,") };
            auto dll{ arg.substr(0, br) };
            auto dllpath{ FileSystem::SearchPathExecutable(dll) };

            FileSystem::File dllfile{ *dllpath };
            if(!dllpath || !dllfile.GetFileSigned()) {
                LOG_INFO(2, "rundll32 found to be executing " << dll);
                return true;
            }

            if(hashmap.count(L"Shell32.dll") && hashmap.at(L"Shell32.dll") == dllfile.GetSHA256Hash() &&
               br != std::wstring::npos) {
                auto start{ arg.find_first_not_of(L" ,\t", br) };
                auto func{ arg.substr(start, arg.find_first_of(L" ,\t", start)) };
                LOG_INFO(3, "rundll32 found to be executing shell32");
                return !CompareIgnoreCaseW(func, L"SHCreateLocalServerRunDll");
            } else {
                LOG_INFO(2, "rundll32 found to be executing " << dll);
                return true;
            }
        }
        return false;
    }

    LOG_VERBOSE(3, "Checking if " << executable << " is mmc.exe");
    if(hashmap.count(L"Mmc.exe") && hashmap.at(L"Mmc.exe") == hash) {
        for(auto& arg : args) {
            if(FileSystem::SearchPathExecutable(arg)) {
                LOG_INFO(3, "mmc found to be executing " << arg);
                return true;
            }
        }
        return false;
    }

    LOG_VERBOSE(3, "Checking if " << executable << " is presentationhost");
    if(hashmap.count(L"Presentationhost.exe") && hashmap.at(L"Presentationhost.exe") == hash) {
        for(auto& arg : args) {
            if(FileSystem::SearchPathExecutable(arg)) {
                LOG_INFO(3, "PresentationHost found to be executing " << arg);
                return true;
            }
        }
        return false;
    }

    LOG_VERBOSE(3, "Checking if " << executable << " is Mshta.exe");
    if(hashmap.count(L"Mshta.exe") && hashmap.at(L"Mshta.exe") == hash) {
        return args.size();
    }

    LOG_VERBOSE(3, "Checking if " << executable << " is Msiexec.exe");
    if(hashmap.count(L"Msiexec.exe") && hashmap.at(L"Msiexec.exe") == hash){
        return args.size() && args[0] != L"/V";
    }

    LOG_VERBOSE(3, "Checking if " << executable << " is explorer.exe");
    if(hashmap.count(L"explorer.exe") && hashmap.at(L"explorer.exe") == hash) {
        for(auto& arg : args) {
            if(FileSystem::SearchPathExecutable(arg)) {
                LOG_INFO(2, "explorer found to be executing " << arg);
                return true;
            }
        }
        return false;
    } else{
        return true;
    }
}
