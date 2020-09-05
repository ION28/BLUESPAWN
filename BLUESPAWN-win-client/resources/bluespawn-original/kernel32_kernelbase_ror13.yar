rule kernel32_kernelbase_dll_ror13 {
	meta:
		description = "Detects ROR13 encoded hashes for kernel32/kernelbase functions"
		license = "BSD-3"
		author = "Jake Smith"
		date = "2020-03-26"

	strings:
		$dllname_kernel32_ror13_upper = { 5B BC 4A 6A }
		$dllname_kernel32_ror13_lower = { 6F FD 5A BF }
		$dllname_kernelbase_ror13_upper = { E3 BA EF 2D }
		$dllname_kernelbase_ror13_lower = { 38 FC 40 83 }
		
		$kernel32_ror13_function_CallNamedPipeA = { 3F A0 1B 5A }
		$kernel32_ror13_function_CallNamedPipeW = { 55 A0 1B 5A }
		$kernel32_ror13_function_CheckElevation = { 03 97 5F 14 }
		$kernel32_ror13_function_CheckElevationEnabled = { FE 0B 35 54 }
		$kernel32_ror13_function_CheckRemoteDebuggerPresent = { 80 7D AF 43 }
		$kernel32_ror13_function_ConnectNamedPipe = { F9 C9 09 CB }
		$kernel32_ror13_function_CreateFile2 = { 96 17 00 7C }
		$kernel32_ror13_function_CreateFileA = { A5 17 00 7C }
		$kernel32_ror13_function_CreateFileW = { BB 17 00 7C }
		$kernel32_ror13_function_CreateNamedPipeA = { 46 68 2D 0B }
		$kernel32_ror13_function_CreateNamedPipeW = { 5C 68 2D 0B }
		$kernel32_ror13_function_CreatePipe = { 80 8F 0C 17 }
		$kernel32_ror13_function_CreateProcessA = { 72 FE B3 16 }
		$kernel32_ror13_function_CreateProcessAsUserA = { 8B C4 5D 63 }
		$kernel32_ror13_function_CreateProcessAsUserW = { A1 C4 5D 63 }
		$kernel32_ror13_function_CreateProcessInternalA = { 72 FA 4D DB }
		$kernel32_ror13_function_CreateProcessInternalW = { 88 FA 4D DB }
		$kernel32_ror13_function_CreateRemoteThread = { DD 9C BD 72 }
		$kernel32_ror13_function_CreateRemoteThreadEx = { D4 37 8F B1 }
		$kernel32_ror13_function_DeleteFileA = { 25 B0 FF C2 }
		$kernel32_ror13_function_DeleteFileW = { 3B B0 FF C2 }
		$kernel32_ror13_function_EnumerateLocalComputerNamesA = { 36 D2 15 9E }
		$kernel32_ror13_function_EnumerateLocalComputerNamesW = { 4C D2 15 9E }
		$kernel32_ror13_function_GetComputerNameA = { 8F 22 A4 96 }
		$kernel32_ror13_function_GetComputerNameExA = { 26 A5 C8 AC }
		$kernel32_ror13_function_GetComputerNameExW = { 3C A5 C8 AC }
		$kernel32_ror13_function_GetComputerNameW = { A5 22 A4 96 }
		$kernel32_ror13_function_GetCurrentProcess = { E6 17 8F 7B }
		$kernel32_ror13_function_GetCurrentProcessId = { 02 FA 0D E6 }
		$kernel32_ror13_function_GetModuleHandleA = { 04 49 32 D3 }
		$kernel32_ror13_function_GetModuleHandleExA = { 75 42 52 D0 }
		$kernel32_ror13_function_GetModuleHandleExW = { 8B 42 52 D0 }
		$kernel32_ror13_function_GetModuleHandleW = { 1A 49 32 D3 }
		$kernel32_ror13_function_GetProcAddress = { AA FC 0D 7C }
		$kernel32_ror13_function_GetProcAddress2 = { 49 F7 02 78 }
		$kernel32_ror13_function_LoadLibraryA = { 8E 4E 0E EC }
		$kernel32_ror13_function_LoadLibraryExA = { FC A4 53 07 }
		$kernel32_ror13_function_LoadLibraryExW = { 12 A5 53 07 }
		$kernel32_ror13_function_LoadLibraryW = { A4 4E 0E EC }
		$kernel32_ror13_function_LoadModule = { EC 79 F9 BB }
		$kernel32_ror13_function_ReadFile = { 16 65 FA 10 }
		$kernel32_ror13_function_ReadFileEx = { FC 45 C1 40 }
		$kernel32_ror13_function_RegCreateKeyExA = { B4 E6 64 8B }
		$kernel32_ror13_function_RegCreateKeyExW = { CA E6 64 8B }
		$kernel32_ror13_function_RegOpenKeyExA = { 81 EB 4A A8 }
		$kernel32_ror13_function_RegOpenKeyExW = { 97 EB 4A A8 }
		$kernel32_ror13_function_RegSetValueExA = { DD 9A 1C 2D }
		$kernel32_ror13_function_RegSetValueExW = { F3 9A 1C 2D }
		$kernel32_ror13_function_ReplaceFile = { 6C A0 ED 00 }
		$kernel32_ror13_function_ReplaceFileA = { AE 07 60 03 }
		$kernel32_ror13_function_ReplaceFileW = { C4 07 60 03 }
		$kernel32_ror13_function_TerminateProcess = { 83 B9 B5 78 }
		$kernel32_ror13_function_TerminateThread = { 89 6F 01 BD }
		$kernel32_ror13_function_VirtualAlloc = { 54 CA AF 91 }
		$kernel32_ror13_function_VirtualAlloc2 = { 58 A4 53 E5 }

	condition:
		(1 of ($dllname_kernel*)) and (2 of ($kernel32_ror13_function_*))
}