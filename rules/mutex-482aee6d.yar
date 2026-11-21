rule Sightlines_mutex_482aee6d_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-482aee6d"
        date = "2026-11-10"
        campaign = "mutex-482aee6d"
        family = "njrat"
        hash = "671976daf2b4f8f6a04cddbce8841c733ab514db29b854247cceb819558d64dd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-482aee6d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "PDF FILE PREVIEWER Google Translation DESKTOP OPENNER COPYRIGHT 2011 FOR xIMUsOFT." wide
        $s1 = "QPDF FILE PREVIEWER Google Translation DESKTOP OPENNER TRADEMARK 2011 FOR xIMUsOFT" ascii
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s4 = "5PDF FILE PREVIEWER Google Translation DESKTOP OPENNER" ascii
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = ".NET Framework 4.5" ascii
        $s7 = "Segoe UI" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1632256 and 8 of them
}
