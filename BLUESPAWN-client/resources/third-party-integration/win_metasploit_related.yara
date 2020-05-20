import "pe"

rule metasploit_payload_msfpayload
{
	meta:
		description = "This rule detects generic metasploit callback payloads generated with msfpayload"
		Author = "Adam Burt (adam_burt@symantec.com)"
	strings:
		$a1 = "asf"
		$a2 = "release"
		$a3 = "build"
		$a4 = "support"
		$a5 = "ab.pdb"
		$l1 = "WS2_32.dll"
		$l2 = "mswsock"
		$l3 = "ntdll.dll"
		$l4 = "KERNEL32.dll"
		$l5 = "shell32"
		$l6 = "malloc"
		$l7 = "fopen"
		$l8 = "fclose"
		$l9 = "fprintf"
		$l10 = "strncpy"
	condition:
		all of ($l*)
		and all of ($a*)

}


rule metasploit_service_starter
{
	meta:
		description = "This rule detects related metasploit service starters"
		author = "Adam Burt (adam_burt@symantec.com)"
	strings:
		$a1 = "StartServiceCtrlDispatcher"
		$a2 = "RegisterServiceCtrlHandle"
		$a3 = "CloseHandle"
		$a4 = "memset"
		$a5 = "rundll32.exe"
		$a6 = "msvcrt.dll"
	condition:
		pe.sections[3].name == ".bss"
		and pe.sections[3].virtual_size == 0x00000030
		and pe.sections[2].virtual_size == 0x0000001c
		and pe.sections[4].virtual_size == 0x00000224
		and all of them
}
