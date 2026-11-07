rule Sightlines_signer_cert_sha1_ab2b6b8c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-ab2b6b8c"
        date = "2026-11-02"
        campaign = "signer_cert_sha1-ab2b6b8c"
        family = ""
        hash = "004e512cf58ace717bbf980432325a305cf0e662298cbe91a96e98b35506afae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-ab2b6b8c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260706175859Z0c1" ascii
        $s1 = "464223+5060810" ascii
        $s2 = "250918175859Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 27431440 and 3 of them
}
