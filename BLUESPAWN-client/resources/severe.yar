include "bluespawn-original/kernel32_kernelbase_ror13.yar"

/* https://github.com/nsacyber/Mitigating-Web-Shells */
include "third-party-integration/extended.webshell_detection.yara"

/* https://github.com/gentilkiwi/mimikatz */
include "third-party-integration/kiwi_passwords.yar"

/* https://github.com/mikesxrs/Open-Source-YARA-rules/blob/7fe5d74f508d4781737f300557c2ead9b6f2c0c9/adamburt/win_metasploit_related.yara */
include "third-party-integration/win_metasploit_related.yara"

/* https://github.com/stvemillertime/ConventionEngine/blob/master/ConventionEngine.yar */
include "third-party-integration/ConventionEngine.yar"


/* Yara-Rules Project */
include "../external/yara-rules/cve_rules/CVE-2015-1701.yar"
include "../external/yara-rules/cve_rules/CVE-2015-2426.yar"
include "../external/yara-rules/exploit_kits/EK_Angler.yar"
include "../external/yara-rules/exploit_kits/EK_Blackhole.yar"
include "../external/yara-rules/exploit_kits/EK_BleedingLife.yar"
include "../external/yara-rules/exploit_kits/EK_Crimepack.yar"
include "../external/yara-rules/exploit_kits/EK_Eleonore.yar"
include "../external/yara-rules/exploit_kits/EK_Fragus.yar"
include "../external/yara-rules/exploit_kits/EK_Phoenix.yar"
include "../external/yara-rules/exploit_kits/EK_Sakura.yar"
include "../external/yara-rules/exploit_kits/EK_ZeroAcces.yar"
include "../external/yara-rules/exploit_kits/EK_Zerox88.yar"
include "../external/yara-rules/exploit_kits/EK_Zeus.yar"
include "../external/yara-rules/malware/APT_APT3102.yar"
include "../external/yara-rules/malware/APT_Cobalt.yar"
include "../external/yara-rules/malware/APT_Equation.yar"
include "../external/yara-rules/malware/APT_FVEY_ShadowBrokers_Jan17_Screen_Strings.yar"
include "../external/yara-rules/malware/GEN_PowerShell.yar"
include "../external/yara-rules/malware/RANSOM_DoublePulsar_Petya.yar"
include "../external/yara-rules/malware/RAT_Meterpreter_Reverse_Tcp.yar"
include "../external/yara-rules/malware/TOOLKIT_Chinese_Hacktools.yar"
include "../external/yara-rules/malware/TOOLKIT_Gen_powerkatz.yar"
include "../external/yara-rules/malware/TOOLKIT_PassTheHash.yar"
include "../external/yara-rules/malware/TOOLKIT_Powerstager.yar"
include "../external/yara-rules/malware/TOOLKIT_exe2hex_payload.yar"
include "../external/yara-rules/packers/packer.yar"
