rule Sightlines_rich_header_hash_cc407ac9_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-cc407ac9"
        date = "2026-11-12"
        campaign = "rich_header_hash-cc407ac9"
        family = "prometei"
        hash = "01f2741d92af73f3f4929a4bb9c3c036fd917d9b6b9f63c27bd58b5768f68d73"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-cc407ac9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Host Process for Windows Service" wide
        $s1 = "abnormal program termination" ascii
        $s2 = "- floating point not loaded" ascii
        $s3 = "GAIsProcessorFeaturePresent" ascii
        $s4 = "GetLogicalDriveStringsA" ascii
        $s5 = "Copyright (C) 2016" wide
        $s6 = "IsBadWritePtr" ascii
        $s7 = "IsBadCodePtr" ascii
        $s8 = "\\dH1#)AGp{2" ascii
        $s9 = "sqhost.exe" wide
        $s10 = "49s`1xNQP" ascii
        $s11 = "okmLCS[]<" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}
