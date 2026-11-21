rule Sightlines_contacted_4640bfd2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-4640bfd2"
        date = "2026-11-12"
        campaign = "contacted-4640bfd2"
        family = ""
        hash = "27b6bd9dedec74226c88763403fe8c46c32d8d62d1a89c25d867eb0db2b1a3c2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-4640bfd2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed " wide
        $s1 = "SELECT ExecutablePath, ProcessID FROM Win32_Process" wide
        $s2 = "BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}" wide
        $s3 = "BCrypt.BCryptImportKey() failed with status code:{0}" wide
        $s4 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s5 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" wide
        $s6 = "BCrypt.BCryptDecrypt() (get size) failed with status code: {0}" wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "BCrypt.BCryptDecrypt() failed with status code:{0}" wide
        $s9 = "BCrypt.BCryptGetProperty() failed with status code:{0}" wide
        $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s11 = "HARDWARE\\Description\\System\\CentralProcessor\\0" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
