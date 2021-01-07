#include "mitigation/Software.h"
#include "util/configurations/Registry.h"
#include "util/StringUtils.h"

#include <Windows.h>
#include <Msi.h>

#pragma comment(lib, "Msi.lib")

Version::Version(std::initializer_list<uint32_t> list) : version{ std::move(list) }{}
Version::Version(const std::wstring& versionString){
	auto parts{ SplitStringW(versionString.data(), L".") };
	for(const auto& part : parts){
		version.emplace_back(std::stoi(part));
	}
}
bool Version::operator<(const Version& v) const{
	for(int i = 0; i < version.size(); i++){
		if(i >= v.version.size()){
			if(version[i] != 0){
				return false;
			}
		} else{
			if(version[i] > v.version[i]){
				return false;
			} else if(version[i] < v.version[i]){
				return true;
			}
		}
	}
	for(int i = version.size(); i < v.version.size(); i++){
		if(v.version[i] != 0){
			return true;
		}
	}
	return false;
}
bool Version::operator>(const Version& v) const{
	for(int i = 0; i < version.size(); i++){
		if(i >= v.version.size()){
			if(version[i] != 0){
				return true;
			}
		} else{
			if(version[i] > v.version[i]){
				return true;
			} else if(version[i] < v.version[i]){
				return false;
			}
		}
	}
	for(int i = version.size(); i < v.version.size(); i++){
		if(v.version[i] != 0){
			return false;
		}
	}
	return false;
}
bool Version::operator==(const Version& v) const{
	for(int i = 0; i < version.size(); i++){
		if(i >= v.version.size()){
			if(version[i] != 0){
				return false;
			}
		} else{
			if(version[i] != v.version[i]){
				return false;
			}
		}
	}
	for(int i = version.size(); i < v.version.size(); i++){
		if(v.version[i] != 0){
			return false;
		}
	}
	return true;
}
bool Version::operator<=(const Version& v) const{ return !(*this > v); }
bool Version::operator>=(const Version& v) const{ return !(*this < v); }
bool Version::operator!=(const Version& v) const{ return !(*this == v); }

Software::Software(const std::wstring& name, const std::wstring& description) : 
	name{ name }, description{ description }, present{ false }, version{ std::nullopt }{

	if(!name.length()){
		return;
	}

	WCHAR guid[39];
	for(int i = 0; !MsiEnumProductsW(0, guid); i++){
		DWORD length = 0;
		if(ERROR_MORE_DATA == MsiGetProductInfoW(guid, INSTALLPROPERTY_INSTALLEDPRODUCTNAME, nullptr, &length)){
			std::vector<WCHAR> productName(length += 1);
			if(!MsiGetProductInfoW(guid, INSTALLPROPERTY_INSTALLEDPRODUCTNAME, productName.data(), &length) &&
			   name == productName.data()){
				present = true;
				length = 0;
				if(ERROR_MORE_DATA == MsiGetProductInfoW(guid, INSTALLPROPERTY_VERSIONSTRING, nullptr, &length)){
					std::vector<WCHAR> versionString(length += 1);
					if(!MsiGetProductInfoW(guid, INSTALLPROPERTY_VERSIONSTRING, versionString.data(), &length)){
						try{
							version = Version(versionString.data());
						} catch(std::exception& e){
							version = std::nullopt;
						}
					}
				}
			}
		}
	}
}
bool Software::IsPresent() const {
	return present;
}
std::optional<Version> Software::GetVersion() const{
	return version;
}
WindowsOS::WindowsOS() : Software(L"", L"Base Windows operating system"){
	name = L"Windows";

	auto versionInfoKey{ 
		Registry::RegistryKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\WIndows NT\\CurrentVersion") };
	auto majorVer{ *versionInfoKey.GetValue<DWORD>(L"CurrentMajorVersionNumber") };
	auto minorVer{ *versionInfoKey.GetValue<DWORD>(L"CurrentMinorVersionNumber") };
	try{
		auto buildNumber{ 
			static_cast<uint32_t>(std::stoi(*versionInfoKey.GetValue<std::wstring>(L"CurrentBuildNumber"))) };
		version = Version{ majorVer, minorVer, buildNumber };
	} catch(std::exception& e){
		version = Version{ majorVer, minorVer };
	}
}