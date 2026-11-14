rule Sightlines_tlsh_12139177_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-12139177"
        date = "2026-11-10"
        campaign = "tlsh-12139177"
        family = ""
        hash = "2d77d295f931dd9fb657e9cd7ec513c2f500f1dc72672905560644c0b26f5d5e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-12139177.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0/1/2/3/5464748494:4;4<4=4>4?4@4A4B4C4D4E4F4G4JIKILIMINIOIPIQIRISITIUIVIWIXIYIZI[I\\I]I^I`_a_b_c_d_e_" wide
        $s1 = "Strict Chemical Mixing Ratios - Film Development Worksheet" wide
        $s2 = "Example entry loaded: 500 ml tank, 2 reels, developer 1 + 1, stop bath 1 + 4, fixer 1 + 4." wide
        $s3 = "The technician types exact milliliter volumes for developer, stop bath and fixer." wide
        $s4 = "Stop bath duration is zero. Development may carry into the fix." wide
        $s5 = "Peak temperature above 27 Celsius risks grain clumping." wide
        $s6 = "A push of three stops or more will visibly change grain and contrast." wide
        $s7 = "Correct the values above and choose Compute Mix again." wide
        $s8 = ": the prepared volume is more than 150 percent of the working target." wide
        $s9 = "Dev at high Celsius risks uneven development and grain clumping." wide
        $s10 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s11 = "No automatic estimation is applied: every number comes from the values you type." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1691648 and 12 of them
}
