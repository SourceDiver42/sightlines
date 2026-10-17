rule Sightlines_tlsh_09dd0e67_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-09dd0e67"
        date = "2026-10-15"
        campaign = "tlsh-09dd0e67"
        family = ""
        hash = "8b5eba6961642074384f1fbaa1f936cfbc3a5426df129ca85354243bfde048bb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-09dd0e67.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Invalid value for PYTHONUTF8=%s; disabling utf-8 mode!" ascii
        $s1 = "  <assemblyIdentity type=\"win32\" name=\"Built.exe\" processorArchitecture=\"amd64\" version=\"1.0.0.0\"/>" ascii
        $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" language=\"*\" processor" ascii
        $s3 = "Failed to get address for PyObject_CallFunctionObjArgs" ascii
        $s4 = "LOADER: Failed to set the TMP environment variable." ascii
        $s5 = "LOADER: Failed to convert runtime-tmpdir to a wide string." ascii
        $s6 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s7 = "LOADER: Failed to expand environment variables in the runtime-tmpdir." ascii
        $s8 = "PyInstallem: pyi_win32_utils_to_utf8 failed." ascii
        $s9 = "Reported length (%d) of DLL name (%s) length exceeds buffer[%d] space" ascii
        $s10 = "WARNING: file already exists but should not: %s" ascii
        $s11 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12662072 and 12 of them
}
