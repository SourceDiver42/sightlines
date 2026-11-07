rule Sightlines_imphash_6c379e4f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6c379e4f"
        date = "2026-11-06"
        campaign = "imphash-6c379e4f"
        family = ""
        hash = "3fc6d707d553853cfb9d95aa8b1d9838d9e00633e7f970493e968267a6e0afd2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6c379e4f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" ascii
        $s1 = "Jh7*R-}?CylV8" ascii
        $s2 = "0YK8CP(~X(v8S" ascii
        $s3 = ")^CV.wR9bY5'" ascii
        $s4 = "%y'{acZpye;6" ascii
        $s5 = "O;~Aw),98A7H" ascii
        $s6 = ".b+m8agx>~C" ascii
        $s7 = "K(>ch98.ted" ascii
        $s8 = "ia-bx3rm&90" ascii
        $s9 = "3)nMKx<-M%Q" ascii
        $s10 = "JD3>d'pZbs3" ascii
        $s11 = "LC,L2Bit4G&" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 38293504 and 12 of them
}
