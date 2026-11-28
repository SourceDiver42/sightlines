rule Sightlines_imphash_c530b929_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c530b929"
        date = "2026-11-15"
        campaign = "imphash-c530b929"
        family = ""
        hash = "6066cb758d00dfcf29e2e518a3eba4e5780881c34986caee7c4ec65a78f1e33b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c530b929.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[INFO]: ##### AccessBridgeJavaEntryPoints::getAccessibleTableColumn(%p, index=%d)" ascii
        $s1 = "[INFO]: ##### Calling AccessBridgeJavaEntryPoints::getAccessibleTableCellInfo(%p): row=%d, column=%d" ascii
        $s2 = "[INFO]: ##### AccessBridgeJavaEntryPoints::getAccessibleTableRow(%p, index=%d)" ascii
        $s3 = "[INFO]: ##### AccessBridgeJavaEntryPoints::getAccessibleTableIndex(%p, row=%d, col=%d)" ascii
        $s4 = "[INFO]: ##### AccessBridgeJavaEntryPoints::getAccessibleTableColumnSelections(%p, %d, %p)" ascii
        $s5 = "[INFO]: In AccessBridgeJavaEntryPoints::getAccessibleContextFromHWND(%X):" ascii
        $s6 = "[INFO]: In AccessBridgeJavaEntryPoints::getHWNDFromAccessibleContext(%X):" ascii
        $s7 = "[INFO]: ##### AccessBridgeJavaEntryPoints::getAccessibleHyperlinkCount(%X)" ascii
        $s8 = "[INFO]: In AccessBridgeDialog - Got WM_COPYDATA from HWND %p" ascii
        $s9 = "[INFO]: ##### AccessBridgeJavaEntryPoints::getVisibleChildren(%p, startIndex = %d)" ascii
        $s10 = "[INFO]: ##### AccessBridgeJavaEntryPoints::isAccessibleTableColumnSelected(%p, %d)" ascii
        $s11 = "[INFO]: Calling AccessBridgeJavaEntryPoints::getAccessibleTextInfo(%p, %d, %d):" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
