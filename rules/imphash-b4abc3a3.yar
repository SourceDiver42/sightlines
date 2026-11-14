rule Sightlines_imphash_b4abc3a3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b4abc3a3"
        date = "2026-11-07"
        campaign = "imphash-b4abc3a3"
        family = ""
        hash = "01799078d49cc2a7adf63e3683590c83963307f4bb5b8b972d27e860c96a8222"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b4abc3a3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s1 = "crashpad_handler.exe" wide
        $s2 = "gupdater.exe" wide
        $s3 = "rootkit.dll" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}
