rule Sightlines_tlsh_53b2f07c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-53b2f07c"
        date = "2026-10-15"
        campaign = "tlsh-53b2f07c"
        family = ""
        hash = "000f64c571beb3f09c0405125369610585bd0d60056d64c86ebd1efef88d2df0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-53b2f07c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (Buildroot 2021.11-18033-g83947c7bb6) 14.3.0" ascii
        $s1 = "Required key not available" ascii
        $s2 = "Key was rejected by service" ascii
        $s3 = "Key has been revoked" ascii
        $s4 = "/usr/local/bin/bash" ascii
        $s5 = ".note.gnu.property" ascii
        $s6 = "Key has expired" ascii
        $s7 = "/usr/bin/busybox" ascii
        $s8 = "/data/local/tmp" ascii
        $s9 = "/tmp/.Kdat_tmp" ascii
        $s10 = "/usr/bin/bash" ascii
        $s11 = "/usr/bin/sh" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
