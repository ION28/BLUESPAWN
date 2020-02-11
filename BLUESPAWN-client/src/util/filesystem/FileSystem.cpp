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
#include "common/wrappers.hpp"

namespace FileSystem{
	bool CheckFileExists(std::wstring filename) {
		if(INVALID_FILE_ATTRIBUTES == GetFileAttributes(filename.c_str()) && GetLastError() == ERROR_FILE_NOT_FOUND){
			LOG_VERBOSE(3, "File " << filename << " does not exist.");
			return false;
		}
		LOG_VERBOSE(3, "File " << filename << " exists");
		return true;
	}

	DWORD File::SetFilePointer(DWORD64 val) const {
		//Calculate the offset into format needed for SetFilePointer
		long lowerMask = 0xFFFFFFFF;
		DWORD64 upperMask = static_cast<DWORD64>(0xFFFFFFFF) << 32;
		auto lowerVal = static_cast<DWORD>(val & lowerMask);
		auto upperVal = static_cast<DWORD>((val & upperMask) >> 32);
		return ::SetFilePointer(hFile, lowerVal, reinterpret_cast<PLONG>(&upperVal), 0);
	}

	File::File(IN const std::wstring& path) : hFile{ nullptr }{
		FilePath = path;
		LOG_VERBOSE(2, "Attempting to open file: " << path << ".");
		hFile = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
			FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL, nullptr);
		if(!hFile){
			LOG_VERBOSE(2, "Couldn't open file " << path << ".");
			FileExists = false;
		} else {
			LOG_VERBOSE(2, "File " << path << " opened.");
			FileExists = true;
		}
		Attribs.extension = PathFindExtension(path.c_str());
	}

	bool File::Write(IN const LPVOID value, IN const long offset, IN const unsigned long length, __in_opt const bool truncate, __in_opt const bool insert) const {
		SCOPE_LOCK(SetFilePointer(0), ResetFilePointer);
		LOG_VERBOSE(2, "Writing to file " << FilePath << " at " << offset << ". Insert = " << insert);

		if(!FileExists) {
			LOG_ERROR("Can't write to file " << FilePath << ". File doesn't exist");
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
				if(!ReadFile(hFile, buffer, dwCopySize, nullptr, nullptr)){
					LOG_ERROR("Unable to read " << FilePath << " at offset " << dwFileSize - dwCopyOffset - dwCopySize << " (Error " << GetLastError() << ")");
					return false;
				}
				if(SetFilePointer(dwFileSize - dwCopyOffset) == INVALID_SET_FILE_POINTER){
					LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
					return false;
				}
				if(!WriteFile(hFile, buffer, dwCopySize, nullptr, nullptr)){
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

		if(!WriteFile(hFile, value, length, nullptr, nullptr)) {
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
		if(!FileExists) {
			LOG_ERROR("Can't write to " << FilePath << ". File doesn't exist.");
			SetLastError(ERROR_FILE_NOT_FOUND);
			return false;
		}

		if(SetFilePointer(offset) == INVALID_SET_FILE_POINTER) {
			LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
			return false;
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

	std::optional<std::string> File::GetMD5Hash() const {
		LOG_VERBOSE(3, "Attempting to get MD5 hash of " << FilePath);
		if(!FileExists) {
			LOG_ERROR("Can't get MD5 hash of " << FilePath << ". File doesn't exist");
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
		if(FileExists) {
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
			FileExists = false;
			return false;
		}
		LOG_VERBOSE(1, FilePath << " successfully created.");
		FileExists = true;
		return true;
	}

	bool File::Delete() {
		LOG_VERBOSE(1, "Attempting to delete file " << FilePath);
		if(!FileExists) {
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
				FileExists = false;
				return false;
			}
			FileExists = true;
			return false;
		}
		LOG_VERBOSE(1, FilePath << "deleted.");
		FileExists = false;
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

	Folder::Folder(const std::wstring& path) : hCurFile{ nullptr } {
		FolderPath = path;
		std::wstring searchName = FolderPath;
		searchName += L"\\*";
		FolderExists = true;
		hCurFile = FindFirstFileW(searchName.c_str(), &ffd);
		if(hCurFile == INVALID_HANDLE_VALUE) {
			LOG_ERROR("Couldn't open folder " << path);
			FolderExists = false;
		}
		if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			IsFile = false;
		} else {
			IsFile = true;
		}
	}

	bool Folder::MoveToNextFile() {
		if(FindNextFileW(hCurFile, &ffd) != 0) {
			if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				IsFile = false;
			} else {
				IsFile = true;
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
			IsFile = false;
		} else {
			IsFile = true;
		}
		return true;
	}

	std::optional<File> Folder::Open() const {
		if(IsFile) {
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
		if(!IsFile) {
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

	std::vector<File> Folder::GetFiles(IN std::optional<FileSearchAttribs> attribs, IN int recurDepth) {
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
				}
			} else if(recurDepth != 0 && ffd.cFileName != L"." && ffd.cFileName != L".."){
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
			if(!GetCurIsFile() && recurDepth != 0 && ffd.cFileName != L"." && ffd.cFileName != L".."){
				std::vector<Folder> temp;
				std::optional<Folder> f = EnterDir();
				if(f) {
					if(recurDepth == -1) {
						temp = f->GetSubdirectories(recurDepth);
					} else {
						temp = f->GetSubdirectories(recurDepth - 1);
					}
					while(!temp.empty()) {
						auto file = temp.at(temp.size() - 1);
						temp.pop_back();
						toRet.emplace_back(file);
					}
				}
			}
		} while(MoveToNextFile());
		return toRet;
	}
}