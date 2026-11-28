rule Sightlines_contacted_43ab3baf_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-43ab3baf"
        date = "2026-11-22"
        campaign = "contacted-43ab3baf"
        family = "njrat"
        hash = "9afb9f248c09852bacc6e4601e51c20672e033ba9663ecf1b55b246377a4b6ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-43ab3baf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "https://backdoor.blog.curiooso.com" wide
        $s4 = "http://backdoor.blog.curiooso.com" wide
        $s5 = "https://www.blog.curiooso.com" wide
        $s6 = ".NETFramework,Version=v4.8" ascii
        $s7 = "https://c2.blog.curiooso.com" wide
        $s8 = "http://www.blog.curiooso.com" wide
        $s9 = "http://c2.blog.curiooso.com" wide
        $s10 = "https://blog.curiooso.com" wide
        $s11 = "processInformationLength" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
