rule Sightlines_tlsh_8e757f67_remusstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8e757f67"
        date = "2026-11-10"
        campaign = "tlsh-8e757f67"
        family = "remusstealer"
        hash = "0148cf4d87a467dc69577d9fae6f909a24275ad44b3301de382ce073d1c69b34"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8e757f67.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GetNextDlgGroupItem" ascii
        $s1 = "MapVirtualKeyA" ascii
        $s2 = "CreateToolbarEx" ascii
        $s3 = "@2u/@2u0@2up@2" ascii
        $s4 = "T,8B2T$XB2T" ascii
        $s5 = "LateUpdate" ascii
        $s6 = "T<82T$,B2T" ascii
        $s7 = "T482T4XB2T" ascii
        $s8 = "82L$ B2L" ascii
        $s9 = "82T$!B2T" ascii
        $s10 = "82T$-B2T" ascii
        $s11 = "F2L,HD2L" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1831936 and 12 of them
}
