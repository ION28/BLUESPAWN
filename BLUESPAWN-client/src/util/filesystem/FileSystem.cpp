#include "C:\\Users\\Will Mayes\\Documents\\Cyber Security\\BLUESPAWN\\BLUESPAWN-client\\headers\\util\\filesystem\\FileSystem.h"
//#include "util/filesystem/FileSystem.h"
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
//string GetFileContents(LPCWSTR);
//bool HashFileMD5(LPCWSTR, string&);
FileSystem::File::File(IN const LPCWSTR path) {
	FilePath = path;
	hFile = CreateFileW(path, 
		GENERIC_READ | GENERIC_WRITE, 
		0, 
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
	//TODO: Add ability to insert and handle writing past end of file. 
	if (!FileExists) return 0;
	long lowerMask = 0xFFFFFFFF;
	long upperMask = (long)0x7FFFFFFF << 32;
	LONG lowerOffset = offset & lowerMask;
	LONG upperOffset = offset & upperMask;
	PLONG upper;
	DWORD bytesWritten;
	if (upperOffset) {
		upper = &upperOffset;
	}
	else {
		upper = NULL;
	}
	if (SetFilePointer(hFile, lowerOffset, upper, 0) == INVALID_SET_FILE_POINTER) {
		return 0;
	}
	if (!WriteFile(hFile, value, length, &bytesWritten, NULL)) {
		SetFilePointer(hFile, 0, 0, 0);
		return 0;
	}
	SetFilePointer(hFile, 0, 0, 0);
	return 1;
}

short FileSystem::File::Read(OUT LPVOID buffer, IN const long offset, IN const unsigned long amount) {
	if (!FileExists) return 0;
	long lowerMask = 0xFFFFFFFF;
	long upperMask = (long)0x7FFFFFFF << 32;
	LONG lowerOffset = offset & lowerMask;
	LONG upperOffset = offset & upperMask;
	PLONG upper;
	if (upperOffset) {
		upper = &upperOffset;
	}
	else {
		upper = NULL;
	}
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

short FileSystem::File::MakeFile() {
	if (FileExists) return 0;
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
	return 1;
}

short FileSystem::File::RemoveFile() {
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