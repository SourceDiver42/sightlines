rule Sightlines_imphash_3ae41137_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3ae41137"
        date = "2026-11-09"
        campaign = "imphash-3ae41137"
        family = ""
        hash = "5695f468d50ab1d5a2e2cff485428f515e18175c670e037f75419f40d5cf2274"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3ae41137.json"
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
        uint16(0) == 0x5A4D and filesize < 37838594 and 12 of them
}
