rule Sightlines_imphash_4d13a02b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4d13a02b"
        date = "2026-11-15"
        campaign = "imphash-4d13a02b"
        family = ""
        hash = "22c23b64989a6a8cd1873d01aeadb9a0065e665ceb26328d68b47580c0dcccd1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4d13a02b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[INFO]: ##### WinAccessBridge::getAccessibleTableColumn(%X, %016I64X, index=%d)" ascii
        $s1 = "[INFO]: ##### WinAccessBridge::getAccessibleTableColumnDescription(%X, %016I64X, %d)" ascii
        $s2 = "[INFO]: ##### WinAccessBridge::getAccessibleHyperlinkCount(%X, %016I64X)" ascii
        $s3 = "[INFO]: WinAccessBridge::getTopLevelObject(%X, %016I64X)" ascii
        $s4 = "[INFO]: ##### WinAccessBridge::getAccessibleTableRowSelectionCount(%X, %016I64X)" ascii
        $s5 = "[INFO]: ##### WinAccessBridge::getAccessibleTableColumnHeader(%X, %016I64X)" ascii
        $s6 = "[INFO]: ##### WinAccessBridge::getAccessibleTableRow(%X, %016I64X, index=%d)" ascii
        $s7 = "[INFO]: ##### WinAccessBridge::getAccessibleTableRowDescription(%X, %016I64X, %d)" ascii
        $s8 = "[INFO]: ##### WinAccessBridge::getAccessibleTableColumnSelectionCount(%X, %016I64X)" ascii
        $s9 = "[INFO]: in WinAccessBridge::rendezvousWithNewJavaDLL(%p, %X)" ascii
        $s10 = "[INFO]: WinAccessBridge::getVisibleChildrenCount(%X, %016I64X)" ascii
        $s11 = "[INFO]: ##### WinAccessBridge::getAccessibleTableIndex(%X, %016I64X, row=%d, col=%d)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
