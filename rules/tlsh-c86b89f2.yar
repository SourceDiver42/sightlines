rule Sightlines_tlsh_c86b89f2_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c86b89f2"
        date = "2026-11-15"
        campaign = "tlsh-c86b89f2"
        family = "mirai"
        hash = "32946f2cefc655bdf05df024f0b89e30990d343810b98cb3ba4b5e1440bb2aa1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c86b89f2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s3 = "/snap/snapd/15534/usr/lib/snapd/snapd" ascii
        $s4 = "/usr/libexec/openssh/sftp-server" ascii
        $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s6 = "/usr/lib/policykit-1/polkitd" ascii
        $s7 = "/usr/lib/openssh/sftp-server" ascii
        $s8 = "HOST: 255.255.255.255:1900" ascii
        $s9 = "MAN: \"ssdp:discover\"" ascii
        $s10 = "Unknown error Success" ascii
        $s11 = "M-SEARCH * HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
