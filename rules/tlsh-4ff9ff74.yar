rule Sightlines_tlsh_4ff9ff74_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4ff9ff74"
        date = "2026-10-31"
        campaign = "tlsh-4ff9ff74"
        family = ""
        hash = "21b96cca485d255b59bf9afab688b9a98c0a8a38bb978951dec47804a19375fd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4ff9ff74.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s3 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s4 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s5 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s7 = "SPLASH: length of Tk module directory path exceeds maximum path length!" ascii
        $s8 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s9 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s10 = "SPLASH: length of Tcl module directory path exceeds maximum path length!" ascii
        $s11 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9438812 and 12 of them
}
