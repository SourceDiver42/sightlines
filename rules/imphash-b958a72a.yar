rule Sightlines_imphash_b958a72a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b958a72a"
        date = "2026-11-15"
        campaign = "imphash-b958a72a"
        family = ""
        hash = "ce742eeedd9302c789756b5954ca88e2fb4decba12676844382607168e6ed380"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b958a72a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ERROR calling GetAccessibleContextInfo; vmID = %lX, context = %p" ascii
        $s1 = "ERROR: GetAccessibleContextInfo failed for table cell [%d,%d]." ascii
        $s2 = "ERROR: GetAccessibleContextInfo failed for top-level window " ascii
        $s3 = "ERROR: getAccessibleTableColumnHeader failed." ascii
        $s4 = "ERROR: GetAccessibleContextInfo failed for parent" ascii
        $s5 = "ERROR: GetAccessibleSelectionFromContext failed forselection %d" ascii
        $s6 = "ERROR: GetAccessibleContextInfo failed for selection %d" ascii
        $s7 = "ERROR: GetAccessibleTableCellInfo failed." ascii
        $s8 = "ERROR: GetAccessibleContextInfo failed." ascii
        $s9 = "ERROR: getAccessibleTableRowSelections failed." ascii
        $s10 = "Not enough buffer space; remaining information truncated." ascii
        $s11 = "ERROR: GetVisibleChildrenCount failed" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
