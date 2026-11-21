rule Sightlines_imphash_1271a24d_dlagent10
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1271a24d"
        date = "2026-11-11"
        campaign = "imphash-1271a24d"
        family = "dlagent10"
        hash = "14c6e59422a2bf11438d82bf88d1eb8d43f6dd72a9fece20438c644792c85d33"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1271a24d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://go.microsoft.com/fwlink/?linkid=798306" wide
        $s1 = "Invoking fx resolver [%s] hostfxr_main_bundle_startupinfo" wide
        $s2 = "The required library %s could not be found. Searched with root path [%s], environment variable [%s]," wide
        $s3 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\win-x64.Release\\corehost\\apphost\\standalone\\apphost.pdb" ascii
        $s4 = "CreateActCtxW failed using manifest '%s'. Error code: %d" wide
        $s5 = "Invoking fx resolver [%s] hostfxr_main_startupinfo" wide
        $s6 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s" wide
        $s7 = "Bundle header version compatibility check failed." wide
        $s8 = "The managed DLL bound to this executable is: '%s'" wide
        $s9 = "Error: [%s] does not contain any version-numbered child folders" wide
        $s10 = "This executable is not bound to a managed DLL to execute. The binding value is: '%s'" wide
        $s11 = "  - https://aka.ms/dotnet-core-applaunch?" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 4931888 and 12 of them
}
