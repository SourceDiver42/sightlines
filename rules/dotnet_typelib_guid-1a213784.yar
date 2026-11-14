rule Sightlines_dotnet_typelib_guid_1a213784_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-1a213784"
        date = "2026-11-11"
        campaign = "dotnet_typelib_guid-1a213784"
        family = ""
        hash = "24708045645a922c2fa013b022eb2724e2fbb17eeb03044b255b58029db41f3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-1a213784.json"
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
        uint16(0) == 0x5A4D and filesize < 3224576 and 12 of them
}
