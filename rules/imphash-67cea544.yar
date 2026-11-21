rule Sightlines_imphash_67cea544_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-67cea544"
        date = "2026-11-15"
        campaign = "imphash-67cea544"
        family = ""
        hash = "266ce2d6133471a3e5c5435e624ef701e1f28696f58971e0ba5c5f456ffc0d55"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-67cea544.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ERROR: GetAccessibleContextInfo failed for table cell [%d,%d]." ascii
        $s1 = "ERROR: GetAccessibleContextInfo failed for top-level window " ascii
        $s2 = "ERROR: getAccessibleTableColumnHeader failed." ascii
        $s3 = "ERROR: GetAccessibleContextInfo failed for parent" ascii
        $s4 = "ERROR: GetAccessibleSelectionFromContext failed forselection %d" ascii
        $s5 = "ERROR: GetAccessibleContextInfo failed for selection %d" ascii
        $s6 = "Track Table Model Change Property Events" wide
        $s7 = "ERROR: GetAccessibleTableCellInfo failed." ascii
        $s8 = "ERROR: GetAccessibleContextInfo failed." ascii
        $s9 = "Software\\JavaSoft\\Java Development Kit\\jaccessinspector" ascii
        $s10 = "ERROR: getAccessibleTableRowSelections failed." ascii
        $s11 = "Description changed event: old = %ls; new = %ls" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
