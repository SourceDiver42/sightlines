rule Sightlines_tlsh_293b3f53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-293b3f53"
        date = "2026-10-15"
        campaign = "tlsh-293b3f53"
        family = ""
        hash = "5fbb4528eef28960c906ac391af635afda4872b64e262ef904d60f1e560b9321"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-293b3f53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"POLARIS/6.01(BREW 3.1.5;U;en-us;LG;LX265;POLARIS/6.01/WAP;)MMP/2.0 profile/MIDP-201 Configuration /" ascii
        $s1 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; PalmSource/hspr-H102; Blazer/4.0) 16;320x320\"," ascii
        $s2 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 240x320) Opera 8.65 [zh-cn]\"," ascii
        $s3 = "\"SAMSUNG-SGH-A867/A867UCHJ3 SHP/VPP/R5 NetFront/35 SMM-MMS/1.2.0 profile/MIDP-2.0 configuration/CLDC" ascii
        $s4 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1) Opera 7.23  [en-GB]\"," ascii
        $s5 = "\"Mozilla/4.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.7) Gecko/2008398325 Firefox/3.1.4\"," ascii
        $s6 = "\"Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SPH-ip320; Smartphone; 176x220)\"," ascii
        $s7 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1) Opera 7.23 [ru]\"," ascii
        $s8 = "\"Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SCH-i320; Smartphone; 176x220)\"," ascii
        $s9 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; Sprint:PPC-6700) Opera 8.65 [en]\"," ascii
        $s10 = "\"SonyEricssonW950i/R100 Mozilla/4.0 (compatible; MSIE 6.0; Symbian OS; 323) Opera 8.60 [en-US]\"," ascii
        $s11 = "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 320x320)Opera 8.65 [en]\"," ascii
    condition:
        filesize < 1048576 and 12 of them
}
