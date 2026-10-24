rule Sightlines_tlsh_6ca30fb6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ca30fb6"
        date = "2026-10-22"
        campaign = "tlsh-6ca30fb6"
        family = ""
        hash = "09e0f7616dfd2f7eb2876f6ef7331d6dbc78775acd594a94b0397a56717d1fcc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ca30fb6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "JIT compiler disabled, CPU does not support SSE2" ascii
        $s2 = "unknown or malformed optimization flag '%s'" ascii
        $s3 = "PANIC: unprotected error in call to Lua API (" ascii
        $s4 = "Must use luaL_newstate() for 64 bit target" ascii
        $s5 = "ambiguous syntax (function call x new statement)" ascii
        $s6 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s7 = "attempt to yield across C-call boundary" ascii
        $s8 = "NYI: cannot call this C function (yet)" ascii
        $s9 = "wrong number of arguments for function call" ascii
        $s10 = "runtime code generation failed, restricted kernel?" ascii
        $s11 = "attempt to perform arithmetic on '%s' and '%s'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
