rule Sightlines_tlsh_dcd8d92d_hajime
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dcd8d92d"
        date = "2026-11-14"
        campaign = "tlsh-dcd8d92d"
        family = "hajime"
        hash = "34b6c6241907c842b65c9a691aff7351e54332f9501d85cefa372e609b5e3bfe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dcd8d92d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "EFZ|rU8j" ascii
        $s1 = "H@bXGb=?" ascii
        $s2 = "MspMe\"CA" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}
