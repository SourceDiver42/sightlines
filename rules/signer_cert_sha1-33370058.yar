rule Sightlines_signer_cert_sha1_33370058_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-33370058"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-33370058"
        family = ""
        hash = "6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-33370058.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Wlhod2JHOXlaWEl1WlhobElITm9aV3hzT2pvNg==" ascii
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s2 = ".?AV?$basic_filebuf@_WU?$char_traits@_W@std@@@std@@" ascii
        $s3 = "[ERROR] GetTokenInformation TokenLinkedToken: " wide
        $s4 = "[ERROR] DuplicateTokenEx LinkedToken: " wide
        $s5 = "[WARN] SetTokenInformation SessionId: " wide
        $s6 = ".?AV?$basic_ifstream@_WU?$char_traits@_W@std@@@std@@" ascii
        $s7 = "Failed to open Service Control Manager. Error: " wide
        $s8 = "[ERROR] DuplicateTokenEx UserToken: " wide
        $s9 = "[ERROR] GetCurrentUserToken failed: " wide
        $s10 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide
        $s11 = "[ERROR] CreateProcessAsUser failed: " wide
    condition:
        uint16(0) == 0x5A4D and filesize < 4529936 and 12 of them
}
