rule Sightlines_tlsh_6a6c4c45_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6a6c4c45"
        date = "2026-10-17"
        campaign = "tlsh-6a6c4c45"
        family = "asyncrat"
        hash = "0b19b12b0919cf3bb6904355593948a5077f23f81aca05ffebf60f81eb860ea2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6a6c4c45.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ").NETFramework,Version=v4.0,Profile=Client" ascii
        $s1 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s2 = "Invalid message authentication code (MAC)." wide
        $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" ascii
        $s4 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $s5 = "Select * from Win32_ComputerSystem" wide
        $s6 = "masterKey can not be null or empty." wide
        $s7 = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
        $s8 = ".NET Framework 4 Client Profile" ascii
        $s9 = "Select * from AntivirusProduct" wide
        $s10 = "<IsConnected>k__BackingField" ascii
        $s11 = "<HeaderSize>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
