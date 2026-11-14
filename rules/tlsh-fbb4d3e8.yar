rule Sightlines_tlsh_fbb4d3e8_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fbb4d3e8"
        date = "2026-11-12"
        campaign = "tlsh-fbb4d3e8"
        family = "coinminer"
        hash = "044af04899163a03bbdc95c3bc2499129497e74cbf1b3f17b711b4f1fbff4df6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fbb4d3e8.json"
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
        uint16(0) == 0x5A4D and filesize < 1321792 and 12 of them
}
