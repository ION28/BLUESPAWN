//#include "C:\\Users\\Will Mayes\\Documents\\Cyber Security\\BLUESPAWN\\BLUESPAWN-client\\headers\\util\\filesystem\\FileSystem.h"

//#include "C:\\Users\\Will Mayes\\Documents\\Cyber Security\\BLUESPAWN\\BLUESPAWN-client\\headers\\util\\log\Log.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
using namespace FileSystem; 
bool FileSystem::CheckFileExists(LPCWSTR filename) {
	//Function from https://stackoverflow.com/a/4404259/3302799
	GetFileAttributesW(filename);
	if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(filename) &&
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

FileSystem::File::File(IN const LPCWSTR path) {
	FilePath = path;
	LOG_VERBOSE(2, "Attempting to open file: " << path << ".");
	hFile = CreateFileW(path, 
		GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_READ,
		NULL, 
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		DWORD dwStatus = GetLastError();
		LOG_VERBOSE(2, "Couldn't open file " << path << ".");
		FileExists = false;
	}
	else
	{
		LOG_VERBOSE(2, "File " << path << " opened.");
		FileExists = true;
	}
}

short FileSystem::File::Write(IN const LPVOID value, IN const long offset, IN const unsigned long length, IN const bool truncate, IN const bool insert) {
	LOG_VERBOSE(2, "Writing to file " << FilePath << " at " << offset << ". Insert = " << insert);
	if (!FileExists) {
		LOG_ERROR("Can't write to file " << FilePath << ". File doesn't exist");
		return 0;
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
		return 0;
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
					return 0;
				}
				if (!ReadFile(hFile, readBuf, len, &bytesRead, NULL)) {
					LOG_ERROR("Reading from " << FilePath << " failed with error " << GetLastError());
					free(readBuf);
					SetFilePointer(hFile, 0, 0, 0);
					return 0;
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
					return 0;
				}
			}
			//Write last read portion of the file
			if (SetFilePointer(hFile, writeLowerOffset, writeUpper, 0) == INVALID_SET_FILE_POINTER) {
				LOG_ERROR("Can't set file pointer to " << writeOffset << " in file " << FilePath << ".");
				return 0;
			}
			if (!WriteFile(hFile, writeBuf, writeLen, &bytesWritten, NULL)) {
				LOG_ERROR("Failed to write to " << FilePath << " at offset " << writeOffset << " with error " << GetLastError());
				free(readBuf);
				if (i > 0) free(writeBuf);
				SetFilePointer(hFile, 0, 0, 0);
				return 0;
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
			return 0;
		}
		if (!WriteFile(hFile, writeBuf, writeLen, &bytesWritten, NULL)) {
			LOG_ERROR("Failed to write to " << FilePath << " at offset " << writeOffset << " with error " << GetLastError());
			free(writeBuf);
			SetFilePointer(hFile, 0, 0, 0);
			return 0;
		}
		free(writeBuf);
	}
	//Write value over file at specified offset
	else {
		if (!WriteFile(hFile, value, length, &bytesWritten, NULL)) {
			LOG_ERROR("Failed to write to " << FilePath << " at offset " << offset << " with error " << GetLastError());
			SetFilePointer(hFile, 0, 0, 0);
			return 0;
		}
	}
	if (truncate) {
		if (!SetEndOfFile(hFile)) {
			LOG_ERROR("Couldn't truncate file " << FilePath);
			return 0;
		}
	}
	SetFilePointer(hFile, 0, 0, 0);
	LOG_VERBOSE(1, "Successfule wrote to " << FilePath << "at offset" << offset);
	return 1;
}

short FileSystem::File::Read(OUT LPVOID buffer, IN const long offset, IN const unsigned long amount, OUT DWORD& amountRead) {
	LOG_VERBOSE(2, "Attempting to read " << amount << " bytes from " << FilePath << " at offset " << offset);
	if (!FileExists) {
		LOG_ERROR("Can't write to " << FilePath << ". File doesn't exist.");
		return 0;
	}
	//Calculate the offset into format needed for SetFilePointer
	LONG lowerOffset;
	LONG upperOffset;
	PLONG upper;
	File::TranslateLongToFilePointer(offset, lowerOffset, upperOffset, upper);
	if (SetFilePointer(hFile, lowerOffset, upper, 0) == INVALID_SET_FILE_POINTER) {
		LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
		return 0;
	}
	if (!ReadFile(hFile, buffer, amount, &amountRead, NULL)) {
		LOG_ERROR("Failed to read from " << FilePath << " at offset " << offset << " with error " << GetLastError());
		SetFilePointer(hFile, 0, 0, 0);
		return 0;
	}
	LOG_VERBOSE(1, "Successfully wrote " << amount << " bytes to " << FilePath);
	SetFilePointer(hFile, 0, 0, 0);
	return 1;
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

short FileSystem::File::Create() {
	LOG_VERBOSE(1, "Attempting to create file: " << FilePath);
	if (FileExists) {
		LOG_ERROR("Can't create " << FilePath << ". File already exists.");
		return 0;
	}
	hFile = CreateFileW(FilePath,
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
		return 0;
	}
	LOG_VERBOSE(1, FilePath << " successfully created.");
	FileExists = true;
	return 1;
}

short FileSystem::File::Delete() {
	LOG_VERBOSE(1, "Attempting to delete file " << FilePath);
	if (!FileExists) { 
		LOG_ERROR("Can't delete file " << FilePath << ". File doesn't exist");
		return 0; 
	}
	CloseHandle(hFile);
	if (!DeleteFileW(FilePath)) {
		DWORD dwStatus = GetLastError();
		LOG_ERROR("Deleting file " << FilePath << " failed with error " << dwStatus);
		hFile = CreateFileW(FilePath,
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
			return 0;
		}
		FileExists = true;
		return 0;
	}
	LOG_VERBOSE(1, FilePath << "deleted.");
	FileExists = false;
	return 1;
}

short FileSystem::File::ChangeFileLength(IN const long length) {
	LOG_VERBOSE(2, "Attempting to change length of " << FilePath << " to " << length);
	//Calculate the length into format needed for SetFilePointer
	LONG lowerLen;
	LONG upperLen;
	PLONG upper;
	File::TranslateLongToFilePointer(length, lowerLen, upperLen, upper);
	if (!SetFilePointer(hFile, lowerLen, upper, 0)) {
		LOG_ERROR("Couldn't change file pointer to " << length << " in file " << FilePath);
		return 0;
	}
	if (!SetEndOfFile(hFile)) {
		LOG_ERROR("Couldn't change the length of file " << FilePath);
		return 0;
	}
	LOG_VERBOSE(2, "Changed length of " << FilePath << " to " << length);
	return 1;
}

FileSystem::Folder::Folder(LPCWSTR path) {
	FolderPath = path;
	FolderExists = true;
	hCurFile = FindFirstFile(path, &ffd);
	if (hCurFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("Couldn't open folder " << path);
		FolderExists = false;
	}
	if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		std::cout << "IN " << std::endl;
		IsFile = false;
	}
	else {
		IsFile = true;
	}
}

short FileSystem::Folder::moveToNextFile() {
	if (FindNextFileW(hCurFile, &ffd) != 0) {
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			IsFile = false;
		}
		else {
			IsFile = true;
		}
		return 1;
	}
	std::cout << (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) << std::endl;
	std::cout << ffd.cFileName << " " << GetLastError() << std::endl;
	return 0;
}

short FileSystem::Folder::moveToBeginning() {
	hCurFile = FindFirstFileW(FolderPath, &ffd);
	if (hCurFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("Couldn't open folder " << FolderPath);
		return 0;
	}
	if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		IsFile = false;
	}
	else {
		IsFile = true;
	}
	return 1;
}

bool FileSystem::Folder::getCurIsFile() {
	return IsFile;
}

short FileSystem::Folder::Open(OUT File*& file) {
	wstring fileName = ffd.cFileName;
	wstring filePath = FolderPath + fileName;
	file = new File(filePath.c_str());
	if (file->getFileExists()) return 1;
	return 0;
}

short FileSystem::Folder::EnterDir(OUT Folder*& folder) {
	wstring folderName = FolderPath;
	folderName += ffd.cFileName;
	folder = new Folder(folderName.c_str());
	if (folder->getFolderExists()) return 1;
	return 0;
}

bool FileSystem::Folder::getFolderExists() {
	return FolderExists;
}

std::vector<File*>* FileSystem::Folder::GetFiles(IN FileAttribs* attribs, IN int recurDepth) {
	if (moveToBeginning() == 0) {
		std::cout << "Couldn't get to beginning of folder " << FolderPath << std::endl;
		LOG_ERROR("Couldn't get to beginning of folder " << FolderPath);
		return NULL;
	}
	std::vector<File*>* toRet = new std::vector<File*>();
	do {
		if (getCurIsFile()) {
			File* file;
			Open(file);
			if (!attribs) {
				toRet->emplace_back(file);
			}
		}
		else if(recurDepth != 0){
			std::vector<File*>* temp = NULL;
			Folder* folder = NULL;
			EnterDir(folder);
			if (recurDepth == -1) {
				temp = folder->GetFiles(attribs, recurDepth);
			}
			else {
				temp = folder->GetFiles(attribs, recurDepth - 1);
			}
			while (temp && !temp->empty()) {
				File* file = temp->at(temp->size() - 1);
				temp->pop_back();
				toRet->emplace_back(file);
			}
		}
		std::cout << "HERE" << std::endl;
	} while (moveToNextFile());
	return toRet;
}
