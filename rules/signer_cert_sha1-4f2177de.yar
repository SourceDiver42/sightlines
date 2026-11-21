rule Sightlines_signer_cert_sha1_4f2177de_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-4f2177de"
        date = "2026-11-11"
        campaign = "signer_cert_sha1-4f2177de"
        family = ""
        hash = "03d46cba150ef872b53fad1c1979f5b1acd49324933dd785b8daa761578ad882"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-4f2177de.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "VLC media player, VideoLAN and x264 are registered trademarks from VideoLAN" wide
        $s1 = "Copyright (C) the VideoLAN VLC media player developers" ascii
        $s2 = "Licensed under the terms of the GNU Lesser General Public License, version 2.1 or later." ascii
        $s3 = " 1996-2022 VideoLAN and VLC Authors" wide
        $s4 = "*** buffer overflow detected ***: " ascii
        $s5 = "*** stack smashing detected ***: " ascii
        $s6 = "vlc_entry_copyright__3_0_0f" ascii
        $s7 = "vlc_entry_license__3_0_0f" ascii
        $s8 = "VLC media player0/" ascii
        $s9 = "vlc_entry__3_0_0f" ascii
        $s10 = "231218235959Z0C1" ascii
        $s11 = ".gnu_debuglink" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2302192 and 6 of them
}
