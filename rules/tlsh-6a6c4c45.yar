rule Sightlines_tlsh_6a6c4c45_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6a6c4c45"
        date = "2026-11-11"
        campaign = "tlsh-6a6c4c45"
        family = "asyncrat"
        hash = "051013a9da6e240d7e3fb7bb742ed7e83f233b6ef13bd47bed762b117132d696"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6a6c4c45.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ").NETFramework,Version=v4.0,Profile=Client" ascii
        $s1 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s2 = "  <asmv3:application  xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\" >" ascii
        $s3 = "Invalid message authentication code (MAC)." wide
        $s4 = "MessagePackLib.<PrivateImplementationDetails>" ascii
        $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" ascii
        $s6 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $s7 = "1DB2A1F9902B35F8F880EF1692CE9947A193D5A698D8F568BDA721658ED4C58B" ascii
        $s8 = "87639126EA77B358F26532367DBA67C5310EF50A8D9888ED070CD40E1F605A8F" ascii
        $s9 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide
        $s10 = "Select * from Win32_ComputerSystem" wide
        $s11 = "masterKey can not be null or empty." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
