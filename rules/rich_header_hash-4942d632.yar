rule Sightlines_rich_header_hash_4942d632_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-4942d632"
        date = "2026-11-12"
        campaign = "rich_header_hash-4942d632"
        family = ""
        hash = "4ea9ba6549d0e383859372addb0f2750dcbc4a5425191c81b3b676649bd9f0b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-4942d632.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR not set for onefile child process!" ascii
        $s1 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
        $s2 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s3 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s4 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s5 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s6 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s7 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
        $s8 = "LOADER: length of teporary directory path exceeds maximum path length!" wide
        $s9 = "LOADER: failed to create runtime-tmpdir path %ls!" wide
        $s10 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" wide
        $s11 = "Could not load PyInstaller's embedded PKG archive from the executable (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20268160 and 12 of them
}
