rule Sightlines_imphash_2d790d14_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2d790d14"
        date = "2026-10-31"
        campaign = "imphash-2d790d14"
        family = ""
        hash = "8aa2e62ed8ea5473004926743ef7f4ce4a17401037b4a11868d9b9385a781b6a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2d790d14.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Could not resolve CoreCLR path. For more details, enable tracing by setting DOTNET_HOST_TRACE enviro" wide
        $s1 = "Loading deps file... [%s]: is_framework_dependent=%d, use_fallback_graph=%d" wide
        $s2 = "JSON parsing exception: %s [offset %zu: line %d, column %d]" wide
        $s3 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\win-x64.Release\\corehost\\hostpolicy\\standalone\\hostpolicy.p" ascii
        $s4 = "Processing TPA for deps entry [%s, %s, %s, local_path: %s] with fx level: %d" wide
        $s5 = "Processing native/culture for deps entry [%s, %s, %s, local_path: %s]" wide
        $s6 = "  Detected a resource asset, will query <base>/<ietf>/<file_name> base: %s ietf: %s asset: %s" wide
        $s7 = "Failed to create directory [%s] for extracting bundled files. Error code: %d" wide
        $s8 = "    Entry %zu for asset name: %s, relpath: %s, assemblyVersion %s, fileVersion %s, localPath %s" wide
        $s9 = "Files embedded within the bundle will be extracted to [%s] directory." wide
        $s10 = "Unable to open specified trace file for writing: %s" wide
        $s11 = "  %s asset: %s rid=%s assemblyVersion=%s fileVersion=%s localPath=%s" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
