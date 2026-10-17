rule Sightlines_signer_cert_sha1_80c681b1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-80c681b1"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-80c681b1"
        family = ""
        hash = "2e5883a09cfc4391cb81db3f0da4d9b8cda21fc1b287e73a1624ad518d941b94"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-80c681b1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ")Microsoft 3rd Party Application Component0" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "*** buffer overflow detected ***: terminated" ascii
        $s3 = "*** stack smashing detected ***: terminated" ascii
        $s4 = "__imp_IsProcessorFeaturePresent" ascii
        $s5 = "__lib64_libmsvcrt_def_a_iname" ascii
        $s6 = "_head_lib64_libmsvcrt_def_a" ascii
        $s7 = "__imp____mb_cur_max_func" ascii
        $s8 = "260707184831Z0" ascii
        $s9 = "231522+5051180" ascii
        $s10 = "250515184831Z" ascii
        $s11 = "__imp_memset" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4473808 and 12 of them
}
