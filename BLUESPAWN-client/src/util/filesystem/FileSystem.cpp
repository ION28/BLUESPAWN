//#include "C:\\Users\\Will Mayes\\Documents\\Cyber Security\\BLUESPAWN\\BLUESPAWN-client\\headers\\util\\filesystem\\FileSystem.h"
#include "util/filesystem/FileSystem.h"
bool FileSystem::CheckFileExists(LPCWSTR filename) {
	//Function from https://stackoverflow.com/a/4404259/3302799
	GetFileAttributesW(filename);
	if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(filename) &&
		GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		return false;
	}
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
		//printf("Error opening file %s\nError: %d\n", path, dwStatus);
		FileExists = false;
	}
	else
	{
		FileExists = true;
	}
}

short FileSystem::File::Write(IN const LPVOID value, IN const long offset, IN const unsigned long length, IN const bool insert) {
	if (!FileExists) return 0;
	//Calculate the offset into format needed for SetFilePointer
	LONG lowerOffset;
	LONG upperOffset;
	PLONG upper;
	File::TranslateLongToFilePointer(offset, lowerOffset, upperOffset, upper);
	DWORD bytesWritten;
	//Point at the desired offset
	if (SetFilePointer(hFile, lowerOffset, upper, 0) == INVALID_SET_FILE_POINTER) {
		return 0;
	}
	//Insert value into file at specified offset
	if (insert) {
		bool readAll = false;
		long readOffset = offset;
		long writeOffset = offset;
		int i = 0;
		int writeLen = length;
		LPVOID writeBuf = value;
		PLONG writeUpper;
		LONG writeLowerOffset;
		LONG writeUpperOffset;
		File::TranslateLongToFilePointer(writeOffset, writeLowerOffset, writeUpperOffset, writeUpper);
		//Read up to 1000000 bytes at a time until eof is reached, writing the last read chunk between each read. 
		while (!readAll) {
			LPVOID readBuf = calloc(writeLen + 1, 1);
			DWORD bytesRead;
			long len = writeLen;
			//Read to eof file or ~1000000 bytes
			while (true) {
				if (SetFilePointer(hFile, lowerOffset, upper, 0) == INVALID_SET_FILE_POINTER) {
					return 0;
				}
				if (!ReadFile(hFile, readBuf, len, &bytesRead, NULL)) {
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
				readBuf = calloc(len * 2 + 1, 1);
				if (!readBuf) {
					return 0;
				}
//				std::cout << "HERE " << len << std::endl;
			}
			//Write last read portion of the file
			if (SetFilePointer(hFile, writeLowerOffset, writeUpper, 0) == INVALID_SET_FILE_POINTER) {
				return 0;
			}
			if (!WriteFile(hFile, writeBuf, writeLen, &bytesWritten, NULL)) {
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
			free(writeBuf);
			return 0;
		}
		if (!WriteFile(hFile, writeBuf, writeLen, &bytesWritten, NULL)) {
			free(writeBuf);
			SetFilePointer(hFile, 0, 0, 0);
			return 0;
		}
		free(writeBuf);
	}
	//Write value over file at specified offset
	else {
		if (!WriteFile(hFile, value, length, &bytesWritten, NULL)) {
			SetFilePointer(hFile, 0, 0, 0);
			return 0;
		}
	}
	SetFilePointer(hFile, 0, 0, 0);
	return 1;
}

short FileSystem::File::Read(OUT LPVOID buffer, IN const long offset, IN const unsigned long amount) {
	if (!FileExists) return 0;
	//Calculate the offset into format needed for SetFilePointer
	LONG lowerOffset;
	LONG upperOffset;
	PLONG upper;
	File::TranslateLongToFilePointer(offset, lowerOffset, upperOffset, upper);
	DWORD bytesRead;
	if (SetFilePointer(hFile, lowerOffset, upper, 0) == INVALID_SET_FILE_POINTER) {
		return 0;
	}
	if (!ReadFile(hFile, buffer, amount, &bytesRead, NULL)) {
		SetFilePointer(hFile, 0, 0, 0);
		return 0;
	}
	SetFilePointer(hFile, 0, 0, 0);
	return 1;
} 

bool FileSystem::File::GetMD5Hash(OUT string& buffer) {
	if (!FileExists) return false;
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
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		return false;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
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
			printf("CryptHashData failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			return false;
		}
	}

	if (!bResult)
	{
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
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
		//printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	return false;
}

short FileSystem::File::Create() {
	if (FileExists) return 0;
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
		//printf("Error opening file %s\nError: %d\n", FilePath, dwStatus);
		FileExists = false;
		return 0;
	}
	FileExists = true;
	return 1;
}

short FileSystem::File::Delete() {
	if (!FileExists) return 0;
	CloseHandle(hFile);
	if (!DeleteFileW(FilePath)) {
		DWORD dwStatus = GetLastError();
		//printf("Error removing file %s\nError: %d\n", FilePath, dwStatus);
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
			//printf("Error opening file %s\nError: %d\n", FilePath, dwStatus);
			FileExists = false;
			return 0;
		}
		FileExists = true;
		return 0;
	}
	FileExists = false;
	return 1;
}

short FileSystem::File::ChangeFileLength(IN const long length) {
	//Calculate the length into format needed for SetFilePointer
	LONG lowerLen;
	LONG upperLen;
	PLONG upper;
	File::TranslateLongToFilePointer(length, lowerLen, upperLen, upper);
	if (!SetFilePointer(hFile, lowerLen, upper, 0)) return 0;
	if (!SetEndOfFile(hFile)) return 0;
	return 1;

}