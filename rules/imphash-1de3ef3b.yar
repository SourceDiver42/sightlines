rule Sightlines_imphash_1de3ef3b_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1de3ef3b"
        date = "2026-11-03"
        campaign = "imphash-1de3ef3b"
        family = "connectwise"
        hash = "400ff5b9a4439339876282909b23c397ffa208f4bcf64460fa2521284acf0b6e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1de3ef3b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "E:\\delivery\\Dev\\wix37_public\\build\\ship\\x86\\SfxCA.pdb" ascii
        $s1 = "Microsoft.Deployment.WindowsInstaller.EmbeddedUIProxy" wide
        $s2 = "rtedRuntime element in CustomAction.config. If you are binding to .NET 4 or greater add useLegacyV2R" wide
        $s3 = "Failed to create new CA process via RUNDLL32. Error code: %d" wide
        $s4 = "Microsoft.Deployment.WindowsInstaller.CustomActionProxy" wide
        $s5 = "Microsoft.Deployment.WindowsInstaller.Package.dll" ascii
        $s6 = "Failed to invoke EmbeddedUI Initialize method. Error code 0x%X" wide
        $s7 = "zzzzInvokeManagedCustomActionOutOfProcW" ascii
        $s8 = "oFailed to load mscoree.dll (Error code %d). This custom action requires the .NET Framework to be in" wide
        $s9 = "Failed to locate functions in mscoree.dll (Error code %d). This custom action requires the .NET Fram" wide
        $s10 = "Failed to configure app domain setup. Error code 0x%X" wide
        $s11 = "\\Microsoft.Deployment.WindowsInstaller.dll" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2325648 and 12 of them
}
