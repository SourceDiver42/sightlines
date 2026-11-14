rule Sightlines_imphash_6a6d53db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6a6d53db"
        date = "2026-11-12"
        campaign = "imphash-6a6d53db"
        family = ""
        hash = "8318d0a50aeb4498868bdd8241c666db50e0ccf64811c6b7cd96a9e1bd77edd7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6a6d53db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "I/2020/WindowsSettings\"><heapType>SegmentHeap</heapType></asmv3:windowsSettings></asmv3:application>" ascii
        $s1 = "crosoft-com:asm.v3\"><asmv3:application><asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SM" ascii
        $s2 = "@SUVWAVHcA" ascii
        $s3 = "D$ H3L$ H3" ascii
        $s4 = "D$HL9wXt" ascii
        $s5 = "L$HH1D$ " ascii
        $s6 = "UVAUAVAWI" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 7 of them
}
