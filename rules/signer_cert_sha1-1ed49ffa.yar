rule Sightlines_signer_cert_sha1_1ed49ffa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-1ed49ffa"
        date = "2026-11-11"
        campaign = "signer_cert_sha1-1ed49ffa"
        family = ""
        hash = "2640fc0a6a4ccc382765dd56f1b0c0eaf180ae306c32bdf74b4c8a74b757918a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-1ed49ffa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "VLC media player, VideoLAN and x264 are registered trademarks from VideoLAN" wide
        $s1 = " 1996-2018 VideoLAN and VLC Authors" wide
        $s2 = "eement which limit liability and are incorporated herein by reference" wide
        $s3 = "*** buffer overflow detected ***: " ascii
        $s4 = "*** stack smashing detected ***: " ascii
        $s5 = "VLC media player0/" ascii
        $s6 = ".gnu_debuglink" ascii
        $s7 = "libvlccore.dll" ascii
        $s8 = "200911120000Z0C1" ascii
        $s9 = " terminated" ascii
        $s10 = "`@.buildid5" ascii
        $s11 = "241022000000Z0G1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5591440 and 11 of them
}
