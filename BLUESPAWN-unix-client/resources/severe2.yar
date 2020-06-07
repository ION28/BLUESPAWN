/* 

NON-COMMERCIAL

Files under here are licensed under CC BY-NC 4.0 (Non-Commercial): https://creativecommons.org/licenses/by-nc/4.0/
Please remove the below lines and recompile the project to use in a commercial setting.

*/


include "../external/signature-base/yara/apt_cobaltstrike.yar"
include "../external/signature-base/yara/apt_cobaltstrike_evasive.yar"
include "../external/signature-base/yara/crime_emotet.yar"
include "../external/signature-base/yara/exploit_cve_2014_4076.yar"
include "../external/signature-base/yara/exploit_cve_2015_1674.yar"
include "../external/signature-base/yara/exploit_uac_elevators.yar"
include "../external/signature-base/yara/gen_armitage.yar"
include "../external/signature-base/yara/gen_case_anomalies.yar"
include "../external/signature-base/yara/gen_cert_payloads.yar"
include "../external/signature-base/yara/gen_chaos_payload.yar"
include "../external/signature-base/yara/gen_cmd_script_obfuscated.yar"
include "../external/signature-base/yara/gen_empire.yar"
include "../external/signature-base/yara/gen_enigma_protector.yar"
include "../external/signature-base/yara/gen_google_anomaly.yar"
include "../external/signature-base/yara/gen_hta_anomalies.yar"
include "../external/signature-base/yara/gen_impacket_tools.yar"
include "../external/signature-base/yara/gen_invoke_mimikatz.yar"
include "../external/signature-base/yara/gen_invoke_psimage.yar"
include "../external/signature-base/yara/gen_invoke_thehash.yar"
include "../external/signature-base/yara/gen_kerberoast.yar"
include "../external/signature-base/yara/gen_loaders.yar"
include "../external/signature-base/yara/gen_macro_ShellExecute_action.yar"
include "../external/signature-base/yara/gen_mal_link.yar"
include "../external/signature-base/yara/gen_mal_scripts.yar"
include "../external/signature-base/yara/gen_merlin_agent.yar"
include "../external/signature-base/yara/gen_metasploit_loader_rsmudge.yar"
include "../external/signature-base/yara/gen_metasploit_payloads.yar"
include "../external/signature-base/yara/gen_mimikittenz.yar"
include "../external/signature-base/yara/gen_mimipenguin.yar"
include "../external/signature-base/yara/gen_nopowershell.yar"
include "../external/signature-base/yara/gen_p0wnshell.yar"
include "../external/signature-base/yara/gen_powerkatz.yar"
include "../external/signature-base/yara/gen_powershdll.yar"
include "../external/signature-base/yara/gen_powershell_empire.yar"
include "../external/signature-base/yara/gen_powershell_invocation.yar"
include "../external/signature-base/yara/gen_powershell_obfuscation.yar"
include "../external/signature-base/yara/gen_powershell_suite.yar"
include "../external/signature-base/yara/gen_powershell_susp.yar"
include "../external/signature-base/yara/gen_powershell_toolkit.yar"
include "../external/signature-base/yara/gen_powersploit_dropper.yar"
include "../external/signature-base/yara/gen_ps_empire_eval.yar"
include "../external/signature-base/yara/gen_ps_osiris.yar"
include "../external/signature-base/yara/gen_ps1_shellcode.yar"
include "../external/signature-base/yara/gen_rottenpotato.yar"
include "../external/signature-base/yara/gen_shikataganai.yar"
include "../external/signature-base/yara/gen_susp_lnk.yar"
include "../external/signature-base/yara/gen_susp_lnk_files.yar"
include "../external/signature-base/yara/gen_susp_obfuscation.yar"
include "../external/signature-base/yara/gen_susp_xor.yar"
include "../external/signature-base/yara/gen_sysinternals_anomaly.yar"
include "../external/signature-base/yara/gen_unicorn_obfuscated_powershell.yar"
include "../external/signature-base/yara/gen_url_persitence.yar"
include "../external/signature-base/yara/gen_winpayloads.yar"
include "../external/signature-base/yara/gen_wmi_implant.yar"
include "../external/signature-base/yara/gen_xor_hunting.yar"
include "../external/signature-base/yara/generic_dumps.yar"
include "../external/signature-base/yara/generic_exe2hex_payload.yar"
include "../external/signature-base/yara/thor-webshells.yar"
include "../external/signature-base/vendor/yara/airbnb_binaryalert.yar"




/* Excluded due to syntax errors:

general_cloaking.yar
generic_anomalies.yar
thor_inverse_matches.yar
yara_mixed_ext_vars.yar

*/
