rule Sightlines_tlsh_54e5b9c3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-54e5b9c3"
        date = "2026-11-13"
        campaign = "tlsh-54e5b9c3"
        family = ""
        hash = "3d15e680ca51b0918fd96a8e045cc36cdcb01d8c2be8448712839ac574813db5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-54e5b9c3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "RequireApprovalFromUserIfFileMateriallyRenamed" ascii
        $s4 = "oScreenConnect.WindowsBackstageShell, PublicKey=0024000004800000940000000602000000240000525341310004" ascii
        $s5 = "C:\\builds\\cc\\cwcontrol\\Product\\ClientInstallerRunner\\obj\\Release\\ScreenConnect.ClientInstallerRunner" ascii
        $s6 = "001190267f86ad2f0e5b1537ba964464ecc4a97fe33f2a8e0b3b4eb1d1e67ecee991c6ef07bdf55caca293305b1b6d895d19" ascii
        $s7 = "01001190267f86ad2f0e5b1537ba964464ecc4a97fe33f2a8e0b3b4eb1d1e67ecee991c6ef07bdf55caca293305b1b6d895d" ascii
        $s8 = "01190267f86ad2f0e5b1537ba964464ecc4a97fe33f2a8e0b3b4eb1d1e67ecee991c6ef07bdf55caca293305b1b6d895d190" ascii
        $s9 = "1190267f86ad2f0e5b1537ba964464ecc4a97fe33f2a8e0b3b4eb1d1e67ecee991c6ef07bdf55caca293305b1b6d895d1905" ascii
        $s10 = "190267f86ad2f0e5b1537ba964464ecc4a97fe33f2a8e0b3b4eb1d1e67ecee991c6ef07bdf55caca293305b1b6d895d19055" ascii
        $s11 = "1001190267f86ad2f0e5b1537ba964464ecc4a97fe33f2a8e0b3b4eb1d1e67ecee991c6ef07bdf55caca293305b1b6d895d1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
