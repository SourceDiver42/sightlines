rule Sightlines_tlsh_adcd2461_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-adcd2461"
        date = "2026-11-13"
        campaign = "tlsh-adcd2461"
        family = "mirai"
        hash = "0d3782e228425031ded3f3979145a565976f76458884655f3cf0c0ebf9657d87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-adcd2461.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Content-Type: application/json" ascii
        $s1 = "GET /api/v1/status HTTP/1.1" ascii
        $s2 = "POST /api/sync HTTP/1.1" ascii
        $s3 = "Unknown error Success" ascii
        $s4 = "Host: api.svc.local" ascii
        $s5 = "KERN_SECURELEVEL" ascii
        $s6 = "www.example.com" ascii
        $s7 = "GET/dlr." ascii
        $s8 = "/dev/shm/" ascii
        $s9 = "/var/tmp/" ascii
        $s10 = " @N^NuNuNV" ascii
        $s11 = "$_N^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}
