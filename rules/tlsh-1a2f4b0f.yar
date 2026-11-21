rule Sightlines_tlsh_1a2f4b0f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1a2f4b0f"
        date = "2026-11-11"
        campaign = "tlsh-1a2f4b0f"
        family = ""
        hash = "0bdc6590285d46cafdea0cf8f136beeacc120aee708285d2c656a7f615514990"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1a2f4b0f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect" ascii
        $s1 = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(" ascii
        $s2 = "if command -v python3 > /dev/null 2>&1; then" ascii
        $s3 = "if command -v bash > /dev/null 2>&1; then" ascii
        $s4 = "if command -v python > /dev/null 2>&1; then" ascii
        $s5 = "if command -v perl > /dev/null 2>&1; then" ascii
        $s6 = "if command -v sh > /dev/null 2>&1; then" ascii
        $s7 = "if command -v nc > /dev/null 2>&1; then" ascii
        $s8 = "## https://www.revshells.com/ ##" ascii
        $s9 = "#!/bin/bash" ascii
    condition:
        filesize < 1048576 and 10 of them
}
