rule Sightlines_imphash_2e451abe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2e451abe"
        date = "2026-11-24"
        campaign = "imphash-2e451abe"
        family = ""
        hash = "4c2eeae951df9ca391726eeb55269f2a93ed558d3ff7faefcd8103477611f63b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2e451abe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s1 = "3@TList`1.Pack[0]$ActRec<Vcl.Themes.TStyleHookClass>dx[" ascii
        $s2 = "G@TList`1.Pack[1]$ActRec<Vcl.Themes.TStyleManager.TStyleClassDescriptor>lz[" ascii
        $s3 = "MTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TPairEnumerator8UY" ascii
        $s4 = "?TObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>M" ascii
        $s5 = "1@TList`1.Pack[1]$ActRec<System.Classes.TRegGroup>H" ascii
        $s6 = "`TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>'" ascii
        $s7 = "\\TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>'" ascii
        $s8 = "LTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TKeyEnumerator;" ascii
        $s9 = "CTObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>M" ascii
        $s10 = "`TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>(" ascii
        $s11 = "ITDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TPairEnumerator;" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5274256 and 12 of them
}
