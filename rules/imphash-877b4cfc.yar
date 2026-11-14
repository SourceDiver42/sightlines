rule Sightlines_imphash_877b4cfc_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-877b4cfc"
        date = "2026-11-11"
        campaign = "imphash-877b4cfc"
        family = "salatstealer"
        hash = "04a7b02fe612dd8963b2b16f44930e976bf72b04e1bc7200fce8c92e10f807f8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-877b4cfc.json"
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
        $s8 = "manually.</li><br><br>8<li>If the destination folder does not exist, it will be2created automaticall" wide
        $s9 = "<description>WinRAR SFX module</description>" ascii
        $s10 = "    <!--The ID below indicates application support for Windows 10 -->" ascii
        $s11 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 29383750 and 12 of them
}
