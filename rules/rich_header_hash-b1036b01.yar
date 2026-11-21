rule Sightlines_rich_header_hash_b1036b01_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-b1036b01"
        date = "2026-11-15"
        campaign = "rich_header_hash-b1036b01"
        family = ""
        hash = "825d4a6a9cb3524c7473fb7dbe2253eb6c082d4bb5f82d5e82424d1c1b6f5d65"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-b1036b01.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
        $s3 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s4 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s5 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s7 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s8 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s9 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
        $s10 = "LOADER: length of teporary directory path exceeds maximum path length!" wide
        $s11 = "LOADER: failed to create runtime-tmpdir path %ls!" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 27829288 and 12 of them
}
