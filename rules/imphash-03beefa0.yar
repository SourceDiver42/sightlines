rule Sightlines_imphash_03beefa0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-03beefa0"
        date = "2026-11-13"
        campaign = "imphash-03beefa0"
        family = ""
        hash = "1512ef2e9ef1f7f9902151b04990527fc435d20cc4829c949add5ec8b20ade4c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-03beefa0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>XvV" ascii
        $s1 = "function DownloadTemporaryFile(const Url, FileName, RequiredSHA256OfFile: String; const OnDownloadPr" ascii
        $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s3 = "?TObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>M" ascii
        $s4 = "`TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>'" ascii
        $s5 = "\\IEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>" ascii
        $s6 = "\\TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>'" ascii
        $s7 = "LTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TKeyEnumerator;" ascii
        $s8 = "`IEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>" ascii
        $s9 = "eTList<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>.TEmptyFu" ascii
        $s10 = "CTObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>M" ascii
        $s11 = "`TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>(" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6845562 and 12 of them
}
