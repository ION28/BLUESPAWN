/*
    WARNING: Host-based security systems may DETECT this file as malicious!
    Because the text used in these signatures is also used in some malware definitions, this file may be detected as malicious. If this happens, it is recommended that the limited.yara.bin file be used instead. Because limited.yara.bin is a compiled yara ruleset, it is unlikely to trigger host-based security systems

    ADDITIONAL WARNING: These extended rules are EXPECTED to have some false positives. These rules rely on detecting suspicious indicators that are often present in web shell malware but may also occur within benign files. 
*/


private rule b374k
{
    meta:
        author = "Blair Gillam (@blairgillam)"

    strings:
        $string = "b374k"
        $password_var = "$s_pass"
        $default_password = "0de664ecd2be02cdd54234a0d1229b43"

    condition:
        any of them
}

private rule pas_tool
{
    meta:
        author = "US CERT"

    strings:
        $php = "<?php"
        $base64decode = /\='base'\.\(\d+\*\d+\)\.'_de'\.'code'/ 
        $strreplace = "(str_replace("
        $md5 = ".substr(md5(strrev("
        $gzinflate = "gzinflate"
        $cookie = "_COOKIE"
        $isset = "isset"

    condition:
        (filesize > 20KB and filesize < 22KB) and
        #cookie == 2 and
        #isset == 3 and
        all of them
}

private rule pbot
{
    meta:
        author = "Jacob Baines (Tenable)"

    strings:
        $ = "class pBot" ascii
        $ = "function start(" ascii
        $ = "PING" ascii
        $ = "PONG" ascii

    condition:
        all of them
}

private rule passwordProtection
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $md5 = /md5\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{32}['"]/ nocase
        $sha1 = /sha1\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{40}['"]/ nocase
    condition:
        (any of them) 
}

private rule ObfuscatedPhp
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $eval = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/ nocase  // ;eval( <- this is dodgy
        $eval_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/ nocase  // eval/*lol*/( <- this is dodgy
        $b374k = "'ev'.'al'"
        $align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/  //b374k
        $weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/  // weevely3 launcher
        $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/  // http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
        $nano = /\$[a-z0-9-_]+\[[^]]+\]\(/ //https://github.com/UltimateHackers/nano
        $ninja = /base64_decode[^;]+getallheaders/ //https://github.com/UltimateHackers/nano
        $variable_variable = /\${\$[0-9a-zA-z]+}/
        $too_many_chr = /(chr\([\d]+\)\.){8}/  // concatenation of more than eight `chr()`
        $concat = /(\$[^\n\r]+\.){5}/  // concatenation of more than 5 words
        $concat_with_spaces = /(\$[^\n\r]+\. ){5}/  // concatenation of more than 5 words, with spaces
        $var_as_func = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/
        $comment = /\/\*([^*]|\*[^\/])*\*\/\s*\(/  // eval /* comment */ (php_code)
condition:
        (any of them)
}

private rule DodgyPhp
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $basedir_bypass = /curl_init\s*\(\s*["']file:\/\// nocase
        $basedir_bypass2 = "file:file:///" // https://www.intelligentexploit.com/view-details.html?id=8719
        $disable_magic_quotes = /set_magic_quotes_runtime\s*\(\s*0/ nocase

        $execution = /\b(eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?)\s*\(\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase  // function that takes a callback as 1st parameter
        $execution2 = /\b(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)\s*\(\s*[^,]+,\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase  // functions that takes a callback as 2nd parameter
        $execution3 = /\b(array_(diff|intersect)_u(key|assoc)|array_udiff)\s*\(\s*([^,]+\s*,?)+\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))\s*\[[^]]+\]\s*\)+\s*;/ nocase  // functions that takes a callback as 2nd parameter

        $htaccess = "SetHandler application/x-httpd-php"
        $iis_com = /IIS:\/\/localhost\/w3svc/
        $include = /include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/  // Clever includes
        $ini_get = /ini_(get|set|restore)\s*\(\s*['"](safe_mode|open_basedir|disable_(function|classe)s|safe_mode_exec_dir|safe_mode_include_dir|register_globals|allow_url_include)/ nocase
        $register_function = /register_[a-z]+_function\s*\(\s*['"]\s*(eval|assert|passthru|exec|include|system|shell_exec|`)/  // https://github.com/nbs-system/php-malware-finder/issues/41
        $safemode_bypass = /\x00\/\.\.\/|LD_PRELOAD/
        $shellshock = /\(\)\s*{\s*[a-z:]\s*;\s*}\s*;/
        $udp_dos = /fsockopen\s*\(\s*['"]udp:\/\// nocase
        $various = "<!--#exec cmd="  //http://www.w3.org/Jigsaw/Doc/User/SSI.html#exec
        $at_eval = /@eval\s*\(/ nocase
        $double_var = /\${\s*\${/
        $extract = /extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/
        $reversed = /noitcnuf_etaerc|metsys|urhtssap|edulcni|etucexe_llehs/ nocase
				$silenced_include =/@\s*include\s*/ nocase

    condition:
        (any of them)
}

private rule DangerousPhp
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $system = "system" fullword nocase  // localroot bruteforcers have a lot of this

        $ = "array_filter" fullword nocase
        $ = "assert" fullword nocase
        $ = "backticks" fullword nocase
        $ = "call_user_func" fullword nocase
        $ = "eval" fullword nocase
        $ = "exec" fullword nocase
        $ = "fpassthru" fullword nocase
        $ = "fsockopen" fullword nocase
        $ = "function_exists" fullword nocase
        $ = "getmygid" fullword nocase
        $ = "shmop_open" fullword nocase
        $ = "mb_ereg_replace_callback" fullword nocase
        $ = "passthru" fullword nocase
        $ = /pcntl_(exec|fork)/ fullword nocase
        $ = "php_uname" fullword nocase
        $ = "phpinfo" fullword nocase
        $ = "posix_geteuid" fullword nocase
        $ = "posix_getgid" fullword nocase
        $ = "posix_getpgid" fullword nocase
        $ = "posix_getppid" fullword nocase
        $ = "posix_getpwnam" fullword nocase
        $ = "posix_getpwuid" fullword nocase
        $ = "posix_getsid" fullword nocase
        $ = "posix_getuid" fullword nocase
        $ = "posix_kill" fullword nocase
        $ = "posix_setegid" fullword nocase
        $ = "posix_seteuid" fullword nocase
        $ = "posix_setgid" fullword nocase
        $ = "posix_setpgid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setuid" fullword nocase
        $ = "preg_replace_callback" fullword
        $ = "proc_open" fullword nocase
        $ = "proc_close" fullword nocase
        $ = "popen" fullword nocase
        $ = "register_shutdown_function" fullword nocase
        $ = "register_tick_function" fullword nocase
        $ = "shell_exec" fullword nocase
        $ = "shm_open" fullword nocase
        $ = "show_source" fullword nocase
        $ = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)" nocase
        $ = "stream_socket_pair" nocase
        $ = "suhosin.executor.func.blacklist" nocase
        $ = "unregister_tick_function" fullword nocase
        $ = "win32_create_service" fullword nocase
        $ = "xmlrpc_decode" fullword nocase 
        $ = /ob_start\s*\(\s*[^\)]/  //ob_start('assert'); echo $_REQUEST['pass']; ob_end_flush();

        $whitelist = /escapeshellcmd|escapeshellarg/ nocase

    condition:
        (not $whitelist and (5 of them or #system > 250))
}

private rule IRC
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $ = "USER" fullword nocase
        $ = "PASS" fullword nocase
        $ = "PRIVMSG" fullword nocase
        $ = "MODE" fullword nocase
        $ = "PING" fullword nocase
        $ = "PONG" fullword nocase
        $ = "JOIN" fullword nocase
        $ = "PART" fullword nocase

    condition:
        5 of them
}

private rule base64rule
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $user_agent = "SFRUUF9VU0VSX0FHRU5UCg"
        $eval = "ZXZhbCg"
        $system = "c3lzdGVt"
        $preg_replace = "cHJlZ19yZXBsYWNl"
        $exec = "ZXhlYyg"
        $base64_decode = "YmFzZTY0X2RlY29kZ"
        $perl_shebang = "IyEvdXNyL2Jpbi9wZXJsCg"
        $cmd_exe = "Y21kLmV4ZQ"
        $powershell = "cG93ZXJzaGVsbC5leGU"

    condition:
        any of them
}

private rule hex
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $globals = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" nocase
        $eval = "\\x65\\x76\\x61\\x6C\\x28" nocase
        $exec = "\\x65\\x78\\x65\\x63" nocase
        $system = "\\x73\\x79\\x73\\x74\\x65\\x6d" nocase
        $preg_replace = "\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65" nocase
        $http_user_agent = "\\x48\\124\\x54\\120\\x5f\\125\\x53\\105\\x52\\137\\x41\\107\\x45\\116\\x54" nocase
        $base64_decode = "\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\\x28\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65\\x28" nocase
    
    condition:
        any of them
}

private rule Hpack
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
		$globals = "474c4f42414c53" nocase
        $eval = "6576616C28" nocase
        $exec = "65786563" nocase
        $system = "73797374656d" nocase
        $preg_replace = "707265675f7265706c616365" nocase
        $base64_decode = "61736536345f6465636f646528677a696e666c61746528" nocase
    
    condition:
        any of them
}

private rule strrev
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $globals = "slabolg" nocase fullword
        $preg_replace = "ecalper_gerp" nocase fullword
        $base64_decode = "edoced_46esab" nocase fullword
        $gzinflate = "etalfnizg" nocase fullword
    
    condition:
        any of them
}


private rule SuspiciousEncoding
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    condition:
        (base64rule or hex or strrev or Hpack)
}

private rule DodgyStrings
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
		
    strings:
        $ = ".bash_history"
        $ = /AddType\s+application\/x-httpd-(php|cgi)/ nocase
        $ = /php_value\s*auto_prepend_file/ nocase
        $ = /SecFilterEngine\s+Off/ nocase  // disable modsec
        $ = /Add(Handler|Type|OutputFilter)\s+[^\s]+\s+\.htaccess/ nocase
        $ = ".mysql_history"
        $ = ".ssh/authorized_keys"
        $ = "/(.*)/e"  // preg_replace code execution
        $ = "/../../../"
        $ = "/etc/passwd"
        $ = "/etc/proftpd.conf"
        $ = "/etc/resolv.conf"
        $ = "/etc/shadow"
        $ = "/etc/syslog.conf"
        $ = "/proc/cpuinfo" fullword
        $ = "/var/log/lastlog"
        $ = "/windows/system32/"
        $ = "LOAD DATA LOCAL INFILE" nocase
        $ = "WScript.Shell"
        $ = "WinExec"
        $ = "b374k" fullword nocase
        $ = "backdoor" fullword nocase
        $ = /(c99|r57|fx29)shell/
        $ = /defac(ed|er|ement|ing)/ fullword nocase
        $ = "evilc0ders" fullword nocase
        $ = "exploit" fullword nocase
        $ = "find . -type f" fullword
        $ = "hashcrack" nocase
        $ = "id_rsa" fullword
        $ = "ipconfig" fullword nocase
        $ = "kingdefacer" nocase
        $ = "Wireghoul" nocase fullword
        $ = "LD_PRELOAD" fullword
        $ = "libpcprofile"  // CVE-2010-3856 local root
        $ = "locus7s" nocase
        $ = "ls -la" fullword
        $ = "meterpreter" fullword
        $ = "nc -l" fullword
        $ = "netstat -an" fullword
        $ = "php://"
        $ = "ps -aux" fullword
        $ = "rootkit" fullword nocase
        $ = "slowloris" fullword nocase
        $ = "suhosin" fullword
        $ = "sun-tzu" fullword nocase // quote from the Art of War
        $ = /trojan (payload)?/
        $ = "uname -a" fullword
        $ = "visbot" nocase fullword
        $ = "warez" fullword nocase
        $ = "whoami" fullword
        $ = /(r[e3]v[e3]rs[e3]|w[3e]b|cmd)\s*sh[e3]ll/ nocase
        $ = /-perm -0[24]000/ // find setuid files
        $ = /\/bin\/(ba)?sh/ fullword
        $ = /hack(ing|er|ed)/ nocase
        $ = /(safe_mode|open_basedir) bypass/ nocase
        $ = /xp_(execresultset|regenumkeys|cmdshell|filelist)/

        $vbs = /language\s*=\s*vbscript/ nocase
        $asp = "scripting.filesystemobject" nocase

    condition:
        (IRC or 2 of them)
}

private rule generic_jsp
{
    meta:
        source= "https://www.tenable.com/blog/hunting-for-web-shells"

    strings:
        $ = /Runtime.getRuntime\(\).exec\(request.getParameter\(\"[a-zA-Z0-9]+\"\)\);/ ascii

    condition:
        all of them
}

private rule eval
{
    meta:
        source = "https://www.tenable.com/blog/hunting-for-web-shells"

    strings:
        $ = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/

    condition:
        all of them
}

private rule fopo
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"

    strings:
        $ = /\$[a-zA-Z0-9]+=\"\\(142|x62)\\(141|x61)\\(163|x73)\\(145|x65)\\(66|x36)\\(64|x34)\\(137|x5f)\\(144|x64)\\(145|x65)\\(143|x63)\\(157|x6f)\\(144|x64)\\(145|x65)\";@eval\(/

    condition:
        all of them
}

private rule hardcoded_urldecode
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"

    strings:
        $ = /urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)/

    condition:
        all of them
}

private rule chr_obfuscation
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"

    strings:
        $ = /\$[^=]+=[\t ]*(chr\([0-9]+\)\.?){2,}/

    condition:
        all of them
}

private rule phpInImage
{
    meta:
        source = "Vlad https://github.com/vlad-s"

    strings:
        $php_tag = "<?php"
        $gif = {47 49 46 38 ?? 61} // GIF8[version]a
        $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }
        $jpeg = {FF D8 FF E0 ?? ?? 4A 46 49 46 } 

    condition:
        (($gif at 0) or ($jfif at 0) or ($png at 0) or ($jpeg at 0)) and $php_tag
}

rule hiddenFunctionality
{
    meta:
        author = "NSA Cybersecurity"
        description = "Hidden functionality allows malware to masquerade as another filetype"

    condition:
        phpInImage
}

rule webshellArtifact 
{
    meta:
        author = "NSA Cybersecurity"
        description = "Artifacts common to web shells and rare in benign files"

    condition:
        b374k or pas_tool or pbot or generic_jsp
}

rule suspiciousFunctionality
{
    meta:
        author = "NSA Cybersecurity"
        description = "Artifacts common to web shells and somewhat rare in benign files"

    condition:
        passwordProtection or hardcoded_urldecode or fopo or eval
}

rule obfuscatedFunctionality
{
    meta:
        author = "NSA Cybersecurity"
        description = "Obfuscation sometimes hides malicious functionality"

    condition:
        ObfuscatedPhp or chr_obfuscation or SuspiciousEncoding
}

rule possibleIndicator
{
    meta:
        author = "NSA Cybersecurity"
        description = "Artifacts common to web shells and less common in benign files"

    condition:
		DodgyPhp or DangerousPhp or DodgyStrings
}
