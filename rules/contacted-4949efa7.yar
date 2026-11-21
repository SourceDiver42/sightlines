rule Sightlines_contacted_4949efa7_mmtwstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-4949efa7"
        date = "2026-11-07"
        campaign = "contacted-4949efa7"
        family = "mmtwstealer"
        hash = "0728824543e6b1cc1978059ce98d4577712a1bc9d73386603cf2da9a7d8e0d08"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-4949efa7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "GCC: (Rev13, Built by MSYS2 project) 15.2.0" ascii
        $s2 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s3 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s4 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s5 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s6 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s7 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s8 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
        $s9 = "        <requestedExecutionLevel level=\"asInvoker\"/>" ascii
        $s10 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s11 = "Partial loss of significance (PLOSS)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2964480 and 12 of them
}
