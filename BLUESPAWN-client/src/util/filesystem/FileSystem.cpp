#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "common/StringUtils.h"

#include <windows.h>
#include <Wincrypt.h>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <fileapi.h>
#include <vector>
#include <Shlwapi.h>
#include <SoftPub.h>
#include <mscat.h>
#include "common/wrappers.hpp"

namespace FileSystem{
	bool CheckFileExists(std::wstring filename) {
		auto attribs = GetFileAttributesW(filename.c_str());
		if(INVALID_FILE_ATTRIBUTES == attribs && GetLastError() == ERROR_FILE_NOT_FOUND){
			LOG_VERBOSE(3, "File " << filename << " does not exist.");
			return false;
		}

		if(attribs & FILE_ATTRIBUTE_DIRECTORY){
			LOG_VERBOSE(3, "File " << filename << " is a directory.");
			return false;
		}
		LOG_VERBOSE(3, "File " << filename << " exists");
		return true;
	}

	std::optional<std::wstring> SearchPathExecutable(const std::wstring& name){
		WCHAR* ext = L".exe";
		if(name.size() >= 4 && (name.substr(name.size() - 4) == L".exe" || name.substr(name.size() - 4) == L".dll")){
			ext = nullptr;
		}

		auto size = SearchPathW(nullptr, name.c_str(), ext, 0, nullptr, nullptr);
		if(!size){
			return std::nullopt;
		}

		WCHAR* buffer = new WCHAR[static_cast<size_t>(size) + 1]{};
		WCHAR* filename{};
		if(!SearchPathW(nullptr, name.c_str(), ext, size + 1, buffer, &filename)){
			delete[] buffer;
			return std::nullopt;
		}

		std::wstring path = buffer;
		delete[] buffer;

		return path;
	}

	DWORD File::SetFilePointer(DWORD64 val) const {
		//Calculate the offset into format needed for SetFilePointer
		long lowerMask = 0xFFFFFFFF;
		DWORD64 upperMask = static_cast<DWORD64>(0xFFFFFFFF) << 32;
		auto lowerVal = static_cast<DWORD>(val & lowerMask);
		auto upperVal = static_cast<DWORD>((val & upperMask) >> 32);
		return ::SetFilePointer(hFile, lowerVal, reinterpret_cast<PLONG>(&upperVal), 0);
	}

	bool File::GetFileInSystemCatalogs() const {
		bool bFileFound = false; //Whether the file was found in system catalogs
		HCATADMIN hCatAdmin = NULL; //Context for enumerating system catalogs
		HCATINFO hCatInfo = NULL;
		GUID gAction = DRIVER_ACTION_VERIFY;
		//Hash info
		DWORD dwHashLength = 0; //Length of the hash
		PBYTE pbHash = NULL; //Hash of the file
		if (!CryptCATAdminAcquireContext(&hCatAdmin, &gAction, 0)) {
			LOG_ERROR("Error acquiring catalog admin context " << GetLastError());
			goto end;
		}

		//Get hash length
		if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashLength, NULL, 0)) {
			LOG_ERROR("Error getting hash size " << GetLastError());
			goto end;
		}
		
		//Get the hash of the file
		pbHash = (PBYTE) HeapAlloc(GetProcessHeap(), 0, dwHashLength);
		if (pbHash == NULL) {
			LOG_ERROR("Error allocating " << dwHashLength << " bytes, out of memory.");
			goto end;
		}
		if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashLength, pbHash, 0)) {
			LOG_ERROR("Error getting file hash " << GetLastError());
			goto end;
		}

		//Search catalogs for hash
		hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashLength, 0, &hCatInfo);
		while (hCatInfo != NULL) {
			bFileFound = true;
			CATALOG_INFO ciCatalogInfo = {};
			ciCatalogInfo.cbStruct = sizeof(ciCatalogInfo);

			if (!CryptCATCatalogInfoFromContext(hCatInfo, &ciCatalogInfo, 0))	{
				LOG_ERROR("Couldn't get catalog info for catalog containing hash of file " << FilePath);
				break;
			}

			LOG_VERBOSE(3, "Hash for file " << FilePath << " found in catalog " << ciCatalogInfo.wszCatalogFile);

			hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashLength, 0, &hCatInfo);
		}
	end:
		if (hCatInfo != NULL) CryptCATAdminReleaseCatalogContext(&hCatAdmin, &hCatInfo, 0);
		if (hCatAdmin != NULL) CryptCATAdminReleaseContext(&hCatAdmin, 0);
		if (pbHash != NULL) HeapFree(GetProcessHeap(), 0, pbHash);
		return bFileFound;
	}

	File::File(IN const std::wstring& path) : hFile{ nullptr }{
		FilePath = path;
		LOG_VERBOSE(2, "Attempting to open file: " << path << ".");
		hFile = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
			FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL, nullptr);
		if(!hFile && GetLastError() == ERROR_FILE_NOT_FOUND){
			LOG_VERBOSE(2, "Couldn't open file, file doesn't exist " << path << ".");
			bFileExists = false;
			bWriteAccess = false;
			bReadAccess = false;
		}
		else if (!hFile && GetLastError() == ERROR_ACCESS_DENIED) {
			bWriteAccess = false;
			hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
				FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL, nullptr);
			if (!hFile && GetLastError() == ERROR_FILE_NOT_FOUND) {
				LOG_VERBOSE(2, "Couldn't open file, file doesn't exist " << path << ".");
				bFileExists = false;
				bReadAccess = false;
			}
			else if (!hFile && GetLastError() == ERROR_ACCESS_DENIED) {
				LOG_VERBOSE(2, "Couldn't open file, Access Denied" << path << ".");
				bFileExists = true;
				bReadAccess = false;
			}
			else {
				LOG_VERBOSE(2, "File " << path << " opened.");
				bFileExists = true;
				bReadAccess = true;
			}
		}
		else {
			LOG_VERBOSE(2, "File " << path << " opened.");
			bFileExists = true;
			bWriteAccess = true;
			bReadAccess = true;
		}
		Attribs.extension = PathFindExtension(path.c_str());
	}

	bool File::Write(IN const LPVOID value, IN const long offset, IN const unsigned long length, __in_opt const bool truncate, __in_opt const bool insert) const {
		SCOPE_LOCK(SetFilePointer(0), ResetFilePointer);
		LOG_VERBOSE(2, "Writing to file " << FilePath << " at " << offset << ". Insert = " << insert);

		DWORD dwBytesIO{};

		if(!bFileExists) {
			LOG_ERROR("Can't write to file " << FilePath << ". File doesn't exist");
			SetLastError(ERROR_FILE_NOT_FOUND);
			return false;
		}

		if (!bWriteAccess) {
			LOG_ERROR("Can't write to file " << FilePath << ". Insufficient permissions.");
			SetLastError(ERROR_ACCESS_DENIED);
			return false;
		}

		//Insert value into file at specified offset
		if(insert && !truncate) {
			DWORD64 dwFileSize = GetFileSize();
			for(DWORD64 dwCopyOffset = 0; dwCopyOffset < length; dwCopyOffset += min(1 << 20, length - dwCopyOffset)){
				DWORD dwCopySize = min(1 << 20, length - dwCopyOffset);
				AllocationWrapper buffer = { new char[dwCopySize], dwCopySize, AllocationWrapper::CPP_ARRAY_ALLOC };
				if(SetFilePointer(dwFileSize - dwCopyOffset - dwCopySize) == INVALID_SET_FILE_POINTER){
					LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
					return false;
				}
				if(!ReadFile(hFile, buffer, dwCopySize, &dwBytesIO, nullptr)){
					LOG_ERROR("Unable to read " << FilePath << " at offset " << dwFileSize - dwCopyOffset - dwCopySize << " (Error " << GetLastError() << ")");
					return false;
				}
				if(SetFilePointer(dwFileSize - dwCopyOffset) == INVALID_SET_FILE_POINTER){
					LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
					return false;
				}
				if(!WriteFile(hFile, buffer, dwCopySize, &dwBytesIO, nullptr)){
					LOG_ERROR("Unable to write to " << FilePath << " at offset " << dwFileSize - dwCopyOffset << " (Error " << GetLastError() << ")");
					return false;
				}
			}
		}
		//Write value over file at specified offset
		if(SetFilePointer(offset) == INVALID_SET_FILE_POINTER) {
			LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
			return false;
		}

		if(!WriteFile(hFile, value, length, &dwBytesIO, nullptr)) {
			LOG_ERROR("Failed to write to " << FilePath << " at offset " << offset << " with error " << GetLastError());
			return false;
		}

		if(truncate) {
			if(!SetEndOfFile(hFile)) {
				LOG_ERROR("Couldn't truncate file " << FilePath);
				return false;
			}
		}
		LOG_VERBOSE(1, "Successfule wrote to " << FilePath << "at offset" << offset);
		return true;
	}

	bool File::Read(OUT LPVOID buffer, __in_opt const unsigned long amount, __in_opt const long offset, __out_opt PDWORD amountRead) const {
		SCOPE_LOCK(SetFilePointer(0), ResetFilePointer);
		LOG_VERBOSE(2, "Attempting to read " << amount << " bytes from " << FilePath << " at offset " << offset);
		if(!bFileExists) {
			LOG_ERROR("Can't read from " << FilePath << ". File doesn't exist.");
			SetLastError(ERROR_FILE_NOT_FOUND);
			return false;
		}

		if (!bReadAccess) {
			LOG_ERROR("Can't read from " << FilePath << ". Insufficient permissions.");
			SetLastError(ERROR_ACCESS_DENIED);
			return false;
		}

		if(SetFilePointer(offset) == INVALID_SET_FILE_POINTER) {
			LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
			return false;
		}

		DWORD dwBytesRead{};
		if(!amountRead){
			amountRead = &dwBytesRead;
		}

		if(!ReadFile(hFile, buffer, amount, amountRead, NULL)) {
			LOG_ERROR("Failed to read from " << FilePath << " at offset " << offset << " with error " << GetLastError());
			return false;
		}
		LOG_VERBOSE(1, "Successfully wrote " << amount << " bytes to " << FilePath);
		return true;
	}

	AllocationWrapper File::Read(__in_opt unsigned long amount, __in_opt long offset, __out_opt PDWORD amountRead) const {
		if(amount == -1){
			amount = GetFileSize();
		}
		AllocationWrapper memory = { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, amount + 1), amount + 1, AllocationWrapper::HEAP_ALLOC };
		bool success = Read(memory, amount, offset, amountRead);
		return success ? memory : AllocationWrapper{ nullptr, 0 };
	}

	bool File::MatchesAttributes(IN const FileSearchAttribs& searchAttribs) const {
		if (searchAttribs.extensions.size() > 0) {
			std::wstring ext = ToLowerCaseW(GetFileAttribs().extension);
			if (std::count(searchAttribs.extensions.begin(), searchAttribs.extensions.end(), ext) == 0) {
				return false;
			}
		}

		return true;
	}

	bool File::GetFileSigned() const {
		if (!bFileExists) {
			LOG_ERROR("Can't check file signature for " << FilePath << ". File doesn't exist.");
			SetLastError(ERROR_FILE_NOT_FOUND);
			return false;
		}
		if (!bReadAccess) {
			LOG_ERROR("Can't check file signature for " << FilePath << ". Insufficient permissions.");
			SetLastError(ERROR_ACCESS_DENIED);
			return false;
		}
		WINTRUST_FILE_INFO FileData{};
		FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
		FileData.pcwszFilePath = FilePath.c_str();
		FileData.hFile = hFile;
		FileData.pgKnownSubject = NULL;

		GUID verification = WINTRUST_ACTION_GENERIC_VERIFY_V2;

		WINTRUST_DATA WinTrustData{};

		WinTrustData.cbStruct = sizeof(WinTrustData);
		WinTrustData.pPolicyCallbackData = NULL;
		WinTrustData.pSIPClientData = NULL;
		WinTrustData.dwUIChoice = WTD_UI_NONE;
		WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
		WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
		WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
		WinTrustData.hWVTStateData = NULL;
		WinTrustData.pwszURLReference = NULL;
		WinTrustData.dwUIContext = 0;
		WinTrustData.pFile = &FileData;

		LONG result = WinVerifyTrust((HWND) INVALID_HANDLE_VALUE, &verification, &WinTrustData);
		WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &verification, &WinTrustData);
		if(result == ERROR_SUCCESS){
			LOG_VERBOSE(1, FilePath << " is signed.");
			return true;
		}
		else {
			//Verify signature in system catalog
			bool bInCatalog = File::GetFileInSystemCatalogs();
			if (bInCatalog) {
				LOG_VERBOSE(1, FilePath << " signed in system catalogs.");
				return true;
			}
		}
		LOG_VERBOSE(1, FilePath << " not signed or located in system catalogs.");
		return false;
	}

	std::optional<std::string> File::GetMD5Hash() const {
		LOG_VERBOSE(3, "Attempting to get MD5 hash of " << FilePath);
		if(!bFileExists) {
			LOG_ERROR("Can't get MD5 hash of " << FilePath << ". File doesn't exist");
			SetLastError(ERROR_FILE_NOT_FOUND);
			return std::nullopt;
		}
		if (!bReadAccess) {
			LOG_ERROR("Can't get MD5 hash of " << FilePath << ". Insufficient permissions.");
			SetLastError(ERROR_ACCESS_DENIED);
			return std::nullopt;
		}
		//Function from Microsoft
		//https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/example-c-program--creating-an-md-5-hash-from-file-content
		DWORD dwStatus = 0;
		BOOL bResult = FALSE;
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		BYTE rgbFile[BUFSIZE];
		DWORD cbRead = 0;
		BYTE rgbHash[MD5LEN];
		DWORD cbHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";

		// Get handle to the crypto provider
		if(!CryptAcquireContext(&hProv,
			NULL,
			NULL,
			PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT))
		{
			dwStatus = GetLastError();
			LOG_ERROR("CryptAcquireContext failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
			return std::nullopt;
		}

		if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			dwStatus = GetLastError();
			LOG_ERROR("CryptCreateHash failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
			CryptReleaseContext(hProv, 0);
			return std::nullopt;
		}

		while(bResult = ReadFile(hFile, rgbFile, BUFSIZE,
			&cbRead, NULL))
		{
			if(0 == cbRead)
			{
				break;
			}

			if(!CryptHashData(hHash, rgbFile, cbRead, 0))
			{
				dwStatus = GetLastError();
				LOG_ERROR("CryptHashData failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
				CryptReleaseContext(hProv, 0);
				CryptDestroyHash(hHash);
				return std::nullopt;
			}
		}

		if(!bResult)
		{
			dwStatus = GetLastError();
			LOG_ERROR("ReadFile failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			return std::nullopt;
		}

		std::string buffer = {};

		cbHash = MD5LEN;
		if(CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
		{
			for(DWORD i = 0; i < cbHash; i++)
			{
				buffer += rgbDigits[rgbHash[i] >> 4];
				buffer += rgbDigits[rgbHash[i] & 0xf];
			}
			return buffer;
		} else
		{
			dwStatus = GetLastError();
			LOG_ERROR("CryptGetHashParam failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		LOG_VERBOSE(3, "Successfully got MD5 Hash of " << FilePath);
		return std::nullopt;
	}

	bool File::Create() {
		LOG_VERBOSE(1, "Attempting to create file: " << FilePath);
		if(bFileExists) {
			LOG_ERROR("Can't create " << FilePath << ". File already exists.");
			return false;
		}
		hFile = CreateFileW(FilePath.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			CREATE_NEW,
			FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL,
			NULL);
		if(INVALID_HANDLE_VALUE == hFile)
		{
			DWORD dwStatus = GetLastError();
			LOG_ERROR("Error creating file " << FilePath << ". Error code = " << dwStatus);
			bFileExists = false;
			return false;
		}
		LOG_VERBOSE(1, FilePath << " successfully created.");
		bFileExists = true;
		bReadAccess = true;
		bWriteAccess = true;
		return true;
	}

	bool File::Delete() {
		LOG_VERBOSE(1, "Attempting to delete file " << FilePath);
		if(!bFileExists) {
			LOG_ERROR("Can't delete file " << FilePath << ". File doesn't exist");
			return false;
		}
		CloseHandle(hFile);
		if(!DeleteFileW(FilePath.c_str())) {
			DWORD dwStatus = GetLastError();
			LOG_ERROR("Deleting file " << FilePath << " failed with error " << dwStatus);
			hFile = CreateFileW(FilePath.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				0,
				NULL,
				CREATE_NEW,
				FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL,
				NULL);
			if(INVALID_HANDLE_VALUE == hFile)
			{
				DWORD dwStatus = GetLastError();
				LOG_ERROR("Couldn't reopen " << FilePath << ". Error = " << dwStatus);
				bFileExists = false;
				return false;
			}
			bFileExists = true;
			return false;
		}
		LOG_VERBOSE(1, FilePath << "deleted.");
		bFileExists = false;
		return true;
	}

	bool FileSystem::File::ChangeFileLength(IN const long length) const {
		SCOPE_LOCK(SetFilePointer(0), ResetFilePointer);
		LOG_VERBOSE(2, "Attempting to change length of " << FilePath << " to " << length);

		if(!SetFilePointer(length)) {
			LOG_ERROR("Couldn't change file pointer to " << length << " in file " << FilePath);
			return false;
		}

		if(!SetEndOfFile(hFile)) {
			LOG_ERROR("Couldn't change the length of file " << FilePath);
			return false;
		}
		LOG_VERBOSE(2, "Changed length of " << FilePath << " to " << length);
		return true;
	}

	DWORD64 File::GetFileSize() const {
		DWORD high = {};
		auto size = ::GetFileSize(hFile, &high);
		return (static_cast<DWORD64>(high) << 32) + size;
	}

	std::wstring File::ToString() const {
		return FilePath;
	}

	Folder::Folder(const std::wstring& path) : hCurFile{ nullptr } {
		FolderPath = path;
		std::wstring searchName = FolderPath;
		searchName += L"\\*";
		bFolderExists = true;
		auto f = FindFirstFileW(searchName.c_str(), &ffd);
		hCurFile = { f };
		if(hCurFile == INVALID_HANDLE_VALUE) {
			LOG_ERROR("Couldn't open folder " << path);
			bFolderExists = false;
		}
		if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			bIsFile = false;
		} else {
			bIsFile = true;
		}
	}

	bool Folder::MoveToNextFile() {
		if(FindNextFileW(hCurFile, &ffd) != 0) {
			if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				bIsFile = false;
			} else {
				bIsFile = true;
			}
			return true;
		}
		return false;
	}

	bool Folder::MoveToBeginning() {
		std::wstring searchName = FolderPath;
		searchName += L"\\*";
		hCurFile = FindFirstFileW(searchName.c_str(), &ffd);
		if(hCurFile == INVALID_HANDLE_VALUE) {
			LOG_ERROR("Couldn't open folder " << FolderPath);
			return false;
		}
		if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			bIsFile = false;
		} else {
			bIsFile = true;
		}
		return true;
	}

	std::optional<File> Folder::Open() const {
		if(bIsFile) {
			std::wstring fileName(ffd.cFileName);
			std::wstring filePath(FolderPath);
			filePath += std::wstring(L"\\") + fileName;
			std::wstring out = filePath.c_str();
			File file = FileSystem::File(out);
			if(file.GetFileExists()) {
				return file;
			}
		}
		return std::nullopt;
	}

	std::optional<Folder> Folder::EnterDir() {
		if(!bIsFile) {
			std::wstring folderName = FolderPath;
			folderName += L"\\";
			folderName += ffd.cFileName;
			Folder folder = Folder(folderName.c_str());
			if(folder.GetFolderExists()) return folder;
		}
		return std::nullopt;
	}

	std::optional<File> Folder::AddFile(IN const std::wstring& fileName) const {
		std::wstring filePath = FolderPath;
		std::wstring fName = fileName;
		filePath += L"\\" + fName;
		File file = File(filePath.c_str());
		if(file.GetFileExists()) {
			return file;
		}
		if(file.Create()) {
			return file;
		}
		return std::nullopt;
	}

	bool FileSystem::Folder::RemoveFile() const {
		if(GetCurIsFile()) {
			std::optional<File> f = Open();
			if(f && f->GetFileExists()) {
				if(f->Delete()){
					return true;
				}
			}
		}
		return false;
	}

	std::vector<File> Folder::GetFiles(__in_opt std::optional<FileSearchAttribs> attribs, __in_opt int recurDepth) {
		if(MoveToBeginning() == 0) {
			LOG_ERROR("Couldn't get to beginning of folder " << FolderPath);
			return std::vector<File>();
		}
		std::vector<File> toRet = std::vector<File>();
		do {
			if(GetCurIsFile()) {
				std::optional<File> f = Open();
				if(f) {
					if(!attribs) {
						toRet.emplace_back(*f);
					}
					else {
						if (f->MatchesAttributes(attribs.value())) {
							toRet.emplace_back(*f);
						}
					}
				}
			} else if(recurDepth != 0 && ffd.cFileName != std::wstring{ L"." } && ffd.cFileName != std::wstring{ L".." }){
				std::vector<File> temp;
				std::optional<Folder> f = EnterDir();
				if(f) {
					if(recurDepth == -1) {
						temp = f->GetFiles(attribs, recurDepth);
					} else {
						temp = f->GetFiles(attribs, recurDepth - 1);
					}
					while(!temp.empty()) {
						File file = temp.at(temp.size() - 1);
						temp.pop_back();
						toRet.emplace_back(file);
					}
				}
			}
		} while(MoveToNextFile());
		return toRet;
	}

	std::vector<Folder> Folder::GetSubdirectories(__in_opt int recurDepth) {
		if(MoveToBeginning() == 0) {
			LOG_ERROR("Couldn't get to beginning of folder " << FolderPath);
			return {};
		}
		std::vector<Folder> toRet = {};
		do {
			if(!GetCurIsFile() && recurDepth != 0 && ffd.cFileName != std::wstring{ L"." } && ffd.cFileName != std::wstring{ L".." }){
				std::vector<Folder> temp;
				std::optional<Folder> f = EnterDir();
				if(f.has_value()) {
					toRet.emplace_back(f.value());
					if(recurDepth == -1) {
						temp = f->GetSubdirectories(recurDepth);
					} else {
						temp = f->GetSubdirectories(recurDepth - 1);
					}
					while(!temp.empty()) {
						auto folder = temp.at(temp.size() - 1);
						temp.pop_back();
						toRet.emplace_back(folder);
					}
				}
			}
		} while(MoveToNextFile());
		return toRet;
	}
}