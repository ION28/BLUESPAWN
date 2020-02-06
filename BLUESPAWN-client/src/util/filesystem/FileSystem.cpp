#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "common/StringUtils.h"
using namespace FileSystem; 
bool FileSystem::CheckFileExists(std::wstring filename) {
	//Function from https://stackoverflow.com/a/4404259/3302799
	GetFileAttributesW(filename.c_str());
	if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(filename.c_str()) &&
		GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		LOG_VERBOSE(3, "File " << filename << " does not exist.");
		return false;
	}
	LOG_VERBOSE(3, "File " << filename << " exists");
	return true;
}

void FileSystem::File::TranslateLongToFilePointer(long val, LONG& lowerVal, LONG& upperVal, PLONG& upper) {
	//Calculate the offset into format needed for SetFilePointer
	long lowerMask = 0xFFFFFFFF;
	long upperMask = (long)(0x7FFFFFFF) << 32;
	lowerVal = val & lowerMask;
	upperVal = val & upperMask;
	upper = &upperVal;
}

FileSystem::File::File(IN const std::wstring path) {
	FilePath = path;
	LOG_VERBOSE(2, "Attempting to open file: " << path << ".");
	hFile = CreateFileW(path.c_str(), 
		GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_READ,
		NULL, 
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		LOG_VERBOSE(2, "Couldn't open file " << path << ".");
		FileExists = false;
	}
	else
	{
		LOG_VERBOSE(2, "File " << path << " opened.");
		FileExists = true;
	}
	Attribs.extension = PathFindExtension(path.c_str());
}

bool FileSystem::File::Write(IN const LPVOID value, IN const long offset, IN const unsigned long length, IN const bool truncate, IN const bool insert) {
	LOG_VERBOSE(2, "Writing to file " << FilePath << " at " << offset << ". Insert = " << insert);
	if (!FileExists) {
		LOG_ERROR("Can't write to file " << FilePath << ". File doesn't exist");
		return false;
	}
	//Calculate the offset into format needed for SetFilePointer
	LONG lowerOffset;
	LONG upperOffset;
	PLONG upper;
	File::TranslateLongToFilePointer(offset, lowerOffset, upperOffset, upper);
	DWORD bytesWritten;
	//Point at the desired offset
	if (SetFilePointer(hFile, lowerOffset, upper, 0) == INVALID_SET_FILE_POINTER) {
		LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
		return false;
	}
	//Insert value into file at specified offset
	if (insert && !truncate) {
		bool readAll = false;
		long readOffset = offset;
		long writeOffset = offset;
		int i = 0;
		long writeLen = length;
		LPVOID writeBuf = value;
		PLONG writeUpper;
		LONG writeLowerOffset;
		LONG writeUpperOffset;
		File::TranslateLongToFilePointer(writeOffset, writeLowerOffset, writeUpperOffset, writeUpper);
		//Read up to 1000000 bytes at a time until eof is reached, writing the last read chunk between each read. 
		while (!readAll) {
			LPVOID readBuf = calloc(writeLen + 1l, 1);
			DWORD bytesRead;
			long len = writeLen;
			//Read to eof file or ~1000000 bytes
			while (true) {
				if (SetFilePointer(hFile, lowerOffset, upper, 0) == INVALID_SET_FILE_POINTER) {
					LOG_ERROR("Can't set file pointer to " << readOffset << " in file " << FilePath << ".");
					return false;
				}
				if (!ReadFile(hFile, readBuf, len, &bytesRead, NULL)) {
					LOG_ERROR("Reading from " << FilePath << " failed with error " << GetLastError());
					free(readBuf);
					SetFilePointer(hFile, 0, 0, 0);
					return false;
				}
				if (bytesRead < len) {
					readAll = true;
					break;
				}
				if (len * 2 > 1000000) {
					break;
				}
				free(readBuf);
				len *= 2;
				readBuf = calloc(len * 2l + 1l, 1);
				if (!readBuf) {
					return false;
				}
			}
			//Write last read portion of the file
			if (SetFilePointer(hFile, writeLowerOffset, writeUpper, 0) == INVALID_SET_FILE_POINTER) {
				LOG_ERROR("Can't set file pointer to " << writeOffset << " in file " << FilePath << ".");
				return false;
			}
			if (!WriteFile(hFile, writeBuf, writeLen, &bytesWritten, NULL)) {
				LOG_ERROR("Failed to write to " << FilePath << " at offset " << writeOffset << " with error " << GetLastError());
				free(readBuf);
				if (i > 0) free(writeBuf);
				SetFilePointer(hFile, 0, 0, 0);
				return false;
			}
			//Free last write unless it was the given buffer
			if(i > 0) free(writeBuf);
			//Store the last read in prepartion for next write
			writeBuf = readBuf;
			writeLen = bytesRead;
			//Update the read and write offsets
			writeOffset += bytesWritten;
			File::TranslateLongToFilePointer(writeOffset, writeLowerOffset, writeUpperOffset, writeUpper);
			readOffset += bytesRead;
			File::TranslateLongToFilePointer(readOffset, lowerOffset, upperOffset, upper);
			i++;
		}
		if (SetFilePointer(hFile, writeLowerOffset, writeUpper, 0) == INVALID_SET_FILE_POINTER) {
			LOG_ERROR("Can't set FilePointer to " << writeOffset << " in file " << FilePath << ".");
			free(writeBuf);
			return false;
		}
		if (!WriteFile(hFile, writeBuf, writeLen, &bytesWritten, NULL)) {
			LOG_ERROR("Failed to write to " << FilePath << " at offset " << writeOffset << " with error " << GetLastError());
			free(writeBuf);
			SetFilePointer(hFile, 0, 0, 0);
			return false;
		}
		free(writeBuf);
	}
	//Write value over file at specified offset
	else {
		if (!WriteFile(hFile, value, length, &bytesWritten, NULL)) {
			LOG_ERROR("Failed to write to " << FilePath << " at offset " << offset << " with error " << GetLastError());
			SetFilePointer(hFile, 0, 0, 0);
			return false;
		}
	}
	if (truncate) {
		if (!SetEndOfFile(hFile)) {
			LOG_ERROR("Couldn't truncate file " << FilePath);
			return false;
		}
	}
	SetFilePointer(hFile, 0, 0, 0);
	LOG_VERBOSE(1, "Successfule wrote to " << FilePath << "at offset" << offset);
	return true;
}

bool FileSystem::File::Read(OUT LPVOID buffer, IN const long offset, IN const unsigned long amount, OUT DWORD& amountRead) {
	LOG_VERBOSE(2, "Attempting to read " << amount << " bytes from " << FilePath << " at offset " << offset);
	if (!FileExists) {
		LOG_ERROR("Can't write to " << FilePath << ". File doesn't exist.");
		return false;
	}
	//Calculate the offset into format needed for SetFilePointer
	LONG lowerOffset;
	LONG upperOffset;
	PLONG upper;
	File::TranslateLongToFilePointer(offset, lowerOffset, upperOffset, upper);
	if (SetFilePointer(hFile, lowerOffset, upper, 0) == INVALID_SET_FILE_POINTER) {
		LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
		return false;
	}
	if (!ReadFile(hFile, buffer, amount, &amountRead, NULL)) {
		LOG_ERROR("Failed to read from " << FilePath << " at offset " << offset << " with error " << GetLastError());
		SetFilePointer(hFile, 0, 0, 0);
		return false;
	}
	LOG_VERBOSE(1, "Successfully wrote " << amount << " bytes to " << FilePath);
	SetFilePointer(hFile, 0, 0, 0);
	return true;
} 

bool FileSystem::File::GetMD5Hash(OUT string& buffer) {
	LOG_VERBOSE(3, "Attempting to get MD5 hash of " << FilePath);
	if (!FileExists) {
		LOG_ERROR("Can't get MD5 hash of " << FilePath << ". File doesn't exist");
		return false;
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
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		LOG_ERROR("CryptAcquireContext failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
		return false;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		LOG_ERROR("CryptCreateHash failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
		CryptReleaseContext(hProv, 0);
		return false;
	}

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			LOG_ERROR("CryptHashData failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			return false;
		}
	}

	if (!bResult)
	{
		dwStatus = GetLastError();
		LOG_ERROR("ReadFile failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return false;
	}

	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			buffer += rgbDigits[rgbHash[i] >> 4];
			buffer += rgbDigits[rgbHash[i] & 0xf];
		}
		return true;
	}
	else
	{
		dwStatus = GetLastError();
		LOG_ERROR("CryptGetHashParam failed: " << dwStatus << " while getting MD5 hash of " << FilePath);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	LOG_VERBOSE(3, "Successfully got MD5 Hash of " << FilePath);
	return false;
}

bool FileSystem::File::Create() {
	LOG_VERBOSE(1, "Attempting to create file: " << FilePath);
	if (FileExists) {
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
	if (INVALID_HANDLE_VALUE == hFile)
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

bool FileSystem::File::Delete() {
	LOG_VERBOSE(1, "Attempting to delete file " << FilePath);
	if (!FileExists) { 
		LOG_ERROR("Can't delete file " << FilePath << ". File doesn't exist");
		return false; 
	}
	CloseHandle(hFile);
	if (!DeleteFileW(FilePath.c_str())) {
		DWORD dwStatus = GetLastError();
		LOG_ERROR("Deleting file " << FilePath << " failed with error " << dwStatus);
		hFile = CreateFileW(FilePath.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			CREATE_NEW,
			FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (INVALID_HANDLE_VALUE == hFile)
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

bool FileSystem::File::ChangeFileLength(IN const long length) {
	LOG_VERBOSE(2, "Attempting to change length of " << FilePath << " to " << length);
	//Calculate the length into format needed for SetFilePointer
	LONG lowerLen;
	LONG upperLen;
	PLONG upper;
	File::TranslateLongToFilePointer(length, lowerLen, upperLen, upper);
	if (!SetFilePointer(hFile, lowerLen, upper, 0)) {
		LOG_ERROR("Couldn't change file pointer to " << length << " in file " << FilePath);
		return false;
	}
	if (!SetEndOfFile(hFile)) {
		LOG_ERROR("Couldn't change the length of file " << FilePath);
		return false;
	}
	LOG_VERBOSE(2, "Changed length of " << FilePath << " to " << length);
	return true;
}

FileSystem::Folder::Folder(std::wstring path) {
	FolderPath = path;
	std::wstring searchName = FolderPath;
	searchName += L"\\*";
	FolderExists = true;
	hCurFile = HandleWrapper(FindFirstFile(searchName.c_str(), &ffd));
	if (hCurFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("Couldn't open folder " << path);
		FolderExists = false;
	}
	if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		IsFile = false;
	}
	else {
		IsFile = true;
	}
}

bool FileSystem::Folder::MoveToNextFile() {
	if (FindNextFileW(hCurFile, &ffd) != 0) {
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			IsFile = false;
		}
		else {
			IsFile = true;
		}
		return true;
	}
	return false;
}

bool FileSystem::Folder::MoveToBeginning() {
	wstring searchName = FolderPath;
	searchName += L"\\*";
	hCurFile = FindFirstFileW(searchName.c_str(), &ffd);
	if (hCurFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("Couldn't open folder " << FolderPath);
		return false;
	}
	if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		IsFile = false;
	}
	else {
		IsFile = true;
	}
	return true;
}

std::optional<File> FileSystem::Folder::Open() {
	if (IsFile) {
		wstring fileName(ffd.cFileName);
		wstring filePath(FolderPath);
		filePath += wstring(L"\\") + fileName;
		std::wstring out = filePath.c_str();
		File file = FileSystem::File(out);
		if (file.GetFileExists()) {
			return file;
		}
	}
	return std::nullopt;
}

std::optional<Folder> FileSystem::Folder::EnterDir() {
	if (!IsFile) {
		wstring folderName = FolderPath;
		folderName += L"\\";
		folderName += ffd.cFileName;
		Folder folder = Folder(folderName.c_str());
		if (folder.GetFolderExists()) return folder;
	}
	return std::nullopt;
}

std::optional<File> FileSystem::Folder::AddFile(IN std::wstring fileName) {
	wstring filePath = FolderPath;
	wstring fName = fileName;
	filePath += L"\\" + fName;
	File file = File(filePath.c_str());
	if (file.GetFileExists()) {
		return file;
	}
	if (file.Create()) {
		return file;
	}
	return std::nullopt;
}

bool FileSystem::Folder::RemoveFile() {
	if (GetCurIsFile()) {
		std::optional<File> f = Open();
		if (f) {
			File file = f.value;
			if (file.GetFileExists()) {
				if (file.Delete()){
					return true;
				}
			}
		}
	}
	return false;
}

std::vector<File> FileSystem::Folder::GetFiles(IN FileSearchAttribs* attribs, IN int recurDepth) {
	if (MoveToBeginning() == 0) {
		LOG_ERROR("Couldn't get to beginning of folder " << FolderPath);
		return std::vector<File>();
	}
	std::vector<File> toRet = std::vector<File>();
	do {
		if (GetCurIsFile()) {
			std::optional<File> f = Open();
			if (f) {
				File file = f.value;
				if (!attribs) {
					toRet.emplace_back(file);
				}
				else {
					if (std::count(attribs->extensions.begin(), attribs->extensions.end(), (file.GetFileAttribs().extension))) {
						toRet.emplace_back(file);
					}
				}
			}
		}
		else if(recurDepth != 0 && ffd.cFileName != L"." && ffd.cFileName != L".."){
			std::vector<File> temp;
			std::optional<Folder> f = EnterDir();
			if (f) {
				Folder folder = f.value;
				if (recurDepth == -1) {
					temp = folder.GetFiles(attribs, recurDepth);
				}
				else {
					temp = folder.GetFiles(attribs, recurDepth - 1);
				}
				while (!temp.empty()) {
					File file = temp.at(temp.size() - 1);
					temp.pop_back();
					toRet.emplace_back(file);
				}
			}
		}
	} while (MoveToNextFile());
	return toRet;
}