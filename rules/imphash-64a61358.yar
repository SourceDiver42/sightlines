rule Sightlines_imphash_64a61358_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-64a61358"
        date = "2026-11-09"
        campaign = "imphash-64a61358"
        family = ""
        hash = "08e54c8898bc68d98f0122a4cf71b69858999f32fbc71bdb8a953bffe459af93"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-64a61358.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Failed to get address for PyObject_CallFunctionObjArgs" ascii
        $s1 = "LOADER: Failed to set the TMP environment variable." ascii
        $s2 = "LOADER: Failed to convert runtime-tmpdir to a wide string." ascii
        $s3 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s4 = "LOADER: Failed to expand environment variables in the runtime-tmpdir." ascii
        $s5 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s6 = "Reported length (%d) of DLL name (%s) length exceeds buffer[%d] space" ascii
        $s7 = "WARNING: file already exists but should not: %s" ascii
        $s8 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s9 = "Path of DLL (%s) length exceeds buffer[%d] space" ascii
        $s10 = "SPLASH: Cannot find requirement %s in archive." ascii
        $s11 = "LOADER: Failed to obtain the absolute path of the runtime-tmpdir." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 26508194 and 12 of them
}
