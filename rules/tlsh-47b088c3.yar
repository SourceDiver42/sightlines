rule Sightlines_tlsh_47b088c3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-47b088c3"
        date = "2026-10-15"
        campaign = "tlsh-47b088c3"
        family = ""
        hash = "15821728b711182bded8c2bcbbd3d93521c63119df8d581a2562eb5d5a285642"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-47b088c3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts; SV1)\"," ascii
        $s1 = "\"Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts; SV1; .NET CLR 1.0.3705)" ascii
        $s2 = "\"Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.40; Windows NT 6.0; FunWebProducts; SLCC1" ascii
        $s3 = "\"Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts)\"," ascii
        $s4 = "\"Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SPH-ip320; Smartphone; 176x220)\"," ascii
        $s5 = "\"Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.53; Windows NT 6.0; FunWebProducts; GTB6;" ascii
        $s6 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FunWebProducts-MyWay; SV1; Crazy Browser 1.0.5)\"" ascii
        $s7 = "\"Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SCH-i320; Smartphone; 176x220)\"," ascii
        $s8 = "\"Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.122; Windows NT 5.1; Trident/4.0; FunWebP" ascii
        $s9 = "\"ELinks/0.12~pre5-8 (textmode; Debian; Linux 3.4.0-8.dmz.1-liquorix-amd64 x86_64; 67x35-3)\"," ascii
        $s10 = "\"Mozilla/4.0 (compatible; MSIE 7.0; AOL 7.0; Windows NT 5.1; FunWebProducts)\"," ascii
        $s11 = "\"Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.12; Windows NT 5.1; Trident/4.0; GTB6.3)\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}
