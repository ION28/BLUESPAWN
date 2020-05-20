/*
    WARNING: Host-based security systems may DETECT this file as malicious!
    Because the text used in these signatures is also used in some malware definitions, this file may be detected as malicious. If this happens, it is recommended that the limited.yara.bin file be used instead. Because limited.yara.bin is a compiled yara ruleset, it is unlikely to trigger host-based security systems
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

private rule generic_jsp
{
    meta:
        source = "https://www.tenable.com/blog/hunting-for-web-shells"

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
        chr_obfuscation
}
