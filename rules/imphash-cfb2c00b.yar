rule Sightlines_imphash_cfb2c00b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cfb2c00b"
        date = "2026-11-18"
        campaign = "imphash-cfb2c00b"
        family = ""
        hash = "127a39d2198f17dd9b573904fe7e4040c7c8718753e6c4edee2ff6c35f487fac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cfb2c00b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Convert an IP address in string format (123.45.67.89) to the 32-bit packed binary format used in low" ascii
        $s1 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s2 = "Convert an IP address from 32-bit packed binary format to string format." ascii
        $s3 = "if_nametoindex($self, oname, /)" ascii
        $s4 = "inet_ntoa($self, packed_ip, /)" ascii
        $s5 = "inet_aton($self, ip_addr, /)" ascii
        $s6 = "-level network functions." ascii
        $s7 = "PyTime_AsSecondsDouble" ascii
        $s8 = "_PyCapsule_SetTraverse" ascii
        $s9 = "PyDict_PopString" ascii
        $s10 = "python313.dll" ascii
        $s11 = "PyLong_AsInt" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
