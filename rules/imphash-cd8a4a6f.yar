rule Sightlines_imphash_cd8a4a6f_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cd8a4a6f"
        date = "2026-10-24"
        campaign = "imphash-cd8a4a6f"
        family = "coinminer"
        hash = "0f73cd5b76af3ee8d3f00e30bfadb36290b390e028687525b586e6cb721e561d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cd8a4a6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "7`=t 1#/% 4\"o7TTxcpLe8yPpDxgh67xXSBWJnVu9bW8t7GU:YG_t" ascii
        $s1 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft." ascii
        $s2 = "com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" ascii
        $s3 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" u" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s5 = "iAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application " ascii
        $s6 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\Release\\Crypto.pdb" ascii
        $s7 = "$trogzam kannot bi run in DOS mode$-" ascii
        $s8 = "rulocati_n(0rmtocol v5Rs)ol($`" ascii
        $s9 = "3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" ascii
        $s10 = "6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" ascii
        $s11 = "8 8$8(8,80888<8@8D8H8L8P8T8X8\\8`8d8h8l8p8t8x8|8" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3156992 and 11 of them
}
