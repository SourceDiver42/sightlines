rule Sightlines_tlsh_f300bde5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f300bde5"
        date = "2026-11-12"
        campaign = "tlsh-f300bde5"
        family = ""
        hash = "19dc38ff91fe8ca66cd678cdc66cfba45585e6bdb57f3b8adca00f39e86589ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f300bde5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[io] Calling Platform_SetImeDataFn(): WantVisible: %d, InputPos (%.2f,%.2f) for Viewport 0x%08X" ascii
        $s1 = "(ActiveIdUsing: AllKeyboardKeys: %d, NavDirMask: 0x%X)" ascii
        $s2 = "  - e.g. GlyphExcludeRanges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };" ascii
        $s3 = "SetShortcutRouting(%s, flags=%04X, owner_id=0x%08X) -> always, no register" ascii
        $s4 = "SetShortcutRouting(%s, flags=%04X, owner_id=0x%08X) -> score %d" ascii
        $s5 = "[nav] NavInitRequest: ApplyResult: NavID 0x%08X in Layer %d Window \"%s\"" ascii
        $s6 = "Requires #define IMGUI_ENABLE_FREETYPE + imgui_freetype.cpp." ascii
        $s7 = "SetShortcutRouting(%s, flags=%04X, owner_id=0x%08X) -> filtered as potential char input" ascii
        $s8 = "D:\\VMProtect Ultimate v3.5.0.1213 By Animochacha\\VMProtect_Con.exe" ascii
        $s9 = "Called ImFontAtlas::Build() before ImGuiBackendFlags_RendererHasTextures got set! With new backends:" ascii
        $s10 = "ActiveId: 0x%08X/0x%08X (%.2f sec), AllowOverlap: %d, Source: %s" ascii
        $s11 = "[font] Texture #%03d: update %d regions, texid=0x%I64X, backend_data=0x%I64X" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12713984 and 12 of them
}
