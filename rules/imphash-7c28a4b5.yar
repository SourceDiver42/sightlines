rule Sightlines_imphash_7c28a4b5_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7c28a4b5"
        date = "2026-11-25"
        campaign = "imphash-7c28a4b5"
        family = "valleyrat"
        hash = "0c3abc6ddaa4169fca933bcecb52ec09c949276c47efb7384080cddc69e167b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7c28a4b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" ascii
        $s1 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" wide
        $s2 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s3 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" ascii
        $s4 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "<description>WinRAR SFX module</description>" ascii
        $s6 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
        $s7 = "    <!--The ID below indicates application support for Windows 8 -->" ascii
        $s8 = "    <!--The ID below indicates application support for Windows Vista -->" ascii
        $s9 = "<head><meta http-equiv=\"content-type\" content=\"text/html; charset=" wide
        $s10 = "WaitForMultipleObjects error %d, GetLastError %d" wide
        $s11 = "      name=\"Microsoft.Windows.Common-Controls\"" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11935902 and 12 of them
}
