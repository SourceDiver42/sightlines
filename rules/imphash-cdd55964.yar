rule Sightlines_imphash_cdd55964_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cdd55964"
        date = "2026-11-11"
        campaign = "imphash-cdd55964"
        family = ""
        hash = "ae69309c5e356350ea28d6b71a900bc43ee7e3f7a457d80a1f82efe6c419cc08"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cdd55964.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\EdgeUpdate\\Clients\\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" wide
        $s1 = "WebView2: CoreWebView2Environment failed when trying to call into EmbeddedBrowserWebView.dll. hr=0x" wide
        $s2 = "wWebView2: CoreWebView2Environment failed when trying to LoadLibrary: hr=0x" wide
        $s3 = "WebView2: Failed to find an installed WebView2 runtime or non-stable Microsoft Edge installation." ascii
        $s4 = "GetAvailableCoreWebView2BrowserVersionStringWithOptions" ascii
        $s5 = "\\StringFileInfo\\040904B0\\ProductVersion" wide
        $s6 = "Software\\Policies\\Microsoft\\Edge\\WebView2\\" wide
        $s7 = "WebView2: skipped an incompatible version " ascii
        $s8 = "Copyright Microsoft Corporation. All rights reserved." wide
        $s9 = "Software\\Microsoft\\EdgeUpdate\\ClientState\\" wide
        $s10 = "Microsoft Edge Embedded Browser WebView Loader" wide
        $s11 = "WebView2: Failed to find the app exe path." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
