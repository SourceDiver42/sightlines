rule Sightlines_imphash_8bddb2d0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8bddb2d0"
        date = "2026-11-26"
        campaign = "imphash-8bddb2d0"
        family = ""
        hash = "446205b6c0302ec738b18e027d9343bf454bee9fc2c11672c80fd9d999c423a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8bddb2d0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s3 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s4 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s5 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s6 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s7 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s8 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
        $s9 = "LOADER: length of teporary directory path exceeds maximum path length!" wide
        $s10 = "LOADER: failed to create runtime-tmpdir path %ls!" wide
        $s11 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 28663504 and 12 of them
}
