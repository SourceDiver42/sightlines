rule Sightlines_contacted_1ce0beba_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-1ce0beba"
        date = "2026-11-13"
        campaign = "contacted-1ce0beba"
        family = ""
        hash = "29aacb2efe28d3a4354a3d52a12ecc1ae77146f32abbbd3f718c574ed306bfaa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-1ce0beba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Select * from Win32_ComputerSystem" wide
        $s5 = "CheckRemoteDebuggerPresent" ascii
        $s6 = "<EncryptInitalize>b__0" ascii
        $s7 = "DetectVirtualMachine" ascii
        $s8 = "<EncryptOutput>b__2" ascii
        $s9 = "microsoft corporation" wide
        $s10 = "EncryptOrDecryptXOR" ascii
        $s11 = "isDebuggerPresent" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 13503488 and 12 of them
}
