rule Sightlines_imphash_a53b9d3c_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a53b9d3c"
        date = "2026-11-09"
        campaign = "imphash-a53b9d3c"
        family = "njrat"
        hash = "17bcd09a51bd5e1823409aa8306e8eb51ab7e9b7b3dd1a1d5d68265cbfee1cc9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a53b9d3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" ascii
        $s1 = "D:\\Projects\\WinRAR\\SFX\\build\\sfxrar64\\Release\\sfxrar.pdb" ascii
        $s2 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" wide
        $s3 = "JNot enough memory to unpack the archive with %u GB compression dictionary.+64-bit self-extracting m" wide
        $s4 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s5 = "<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></head>" wide
        $s6 = "    <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s7 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "<description>WinRAR SFX module</description>" ascii
        $s9 = "    <!--The ID below indicates application support for Windows 10 -->" ascii
        $s10 = "manually.</li><br><br>8<li>If the destination folder does not exist, it will be" wide
        $s11 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 24083938 and 12 of them
}
