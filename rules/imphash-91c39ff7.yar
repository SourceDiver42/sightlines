rule Sightlines_imphash_91c39ff7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-91c39ff7"
        date = "2026-11-18"
        campaign = "imphash-91c39ff7"
        family = ""
        hash = "2d13fa4b5ef94464bb94e2ec613eceb5bbad70c8e7e05f0e8ef25f6078397cdc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-91c39ff7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s1 = "_PyDict_GetItemRef_KnownHash_LockHeld" ascii
        $s2 = "_PyDict_SetItem_KnownHash_LockHeld" ascii
        $s3 = "PyObject_ClearManagedDict" ascii
        $s4 = "PyObject_VisitManagedDict" ascii
        $s5 = "PyObject_GetOptionalAttr" ascii
        $s6 = "PyDict_SetDefaultRef" ascii
        $s7 = "python313.dll" ascii
        $s8 = "PyDict_Pop" ascii
        $s9 = "t$XD9r`t'L" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
