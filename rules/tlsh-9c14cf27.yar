rule Sightlines_tlsh_9c14cf27_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9c14cf27"
        date = "2026-11-02"
        campaign = "tlsh-9c14cf27"
        family = ""
        hash = "27470ef9aeeec8a70ed3c5b6beee0663a9be9ed841486cc56d0e43b71999eaac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9c14cf27.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Invoking fx resolver [%s] hostfxr_main_bundle_startupinfo" wide
        $s1 = "CreateActCtxW failed using manifest '%s'. Error code: %d" wide
        $s2 = "Invoking fx resolver [%s] hostfxr_main_startupinfo" wide
        $s3 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s" wide
        $s4 = "Bundle header version compatibility check failed." wide
        $s5 = "The managed DLL bound to this executable is: '%s'" wide
        $s6 = "Error: [%s] does not contain any version-numbered child folders" wide
        $s7 = "This executable is not bound to a managed DLL to execute. The binding value is: '%s'" wide
        $s8 = "  - https://aka.ms/dotnet-core-applaunch?" wide
        $s9 = "Using environment variable %s=[%s] as runtime location." wide
        $s10 = "The required library %s does not support single-file apps." wide
        $s11 = "The library %s was found, but loading it from %s failed" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
