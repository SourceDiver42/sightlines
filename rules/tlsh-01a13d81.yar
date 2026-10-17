rule Sightlines_tlsh_01a13d81_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01a13d81"
        date = "2026-10-17"
        campaign = "tlsh-01a13d81"
        family = ""
        hash = "89dd5e3e026553056d2f2ba0ee40d1de954eb999b76b932645ff3db19ef517c5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01a13d81.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " ascii
        $s1 = "Failed to convert pyhome to ANSI (invalid multibyte string)" ascii
        $s2 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s3 = "Failed to convert pypath to ANSI (invalid multibyte string)" ascii
        $s4 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s5 = "WARNING: file already exists but should not: %s" ascii
        $s6 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s7 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" ascii
        $s8 = "Failed to get address for PyObject_CallFunction" ascii
        $s9 = "Failed to get address for Py_FileSystemDefaultEncoding" ascii
        $s10 = "Failed to get address for PyImport_ExecCodeModule" ascii
        $s11 = "Failed to get address for PyRun_SimpleString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3817006 and 12 of them
}
