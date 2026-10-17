rule Sightlines_tlsh_45ebee99_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-45ebee99"
        date = "2026-10-17"
        campaign = "tlsh-45ebee99"
        family = ""
        hash = "019558221f682a00e6ec301308208096680f0d6d7f8f28b20b1b959f7c4bb924"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-45ebee99.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "7`=t 1#/% 4\"o7TTxcpLe8yPpDxgh67xXSBWJnVu9bW8t7GU:YG_t" ascii
        $s1 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft." ascii
        $s2 = "com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" ascii
        $s3 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" u" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s5 = "iAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application " ascii
        $s6 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\Release\\Crypto.pdb" ascii
        $s7 = "_erfob __gnu[axx::O_CoNcurrefce_ufl/sc_erzkr" ascii
        $s8 = "$trogzam kannot bi run in DOS mode$-" ascii
        $s9 = "rulocati_n(0rmtocol v5Rs)ol($`" ascii
        $s10 = "0__cxxcbit51)_[\"oreigj_exceptiO" ascii
        $s11 = "3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3156992 and 9 of them
}
