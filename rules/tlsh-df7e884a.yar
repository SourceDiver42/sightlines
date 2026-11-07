rule Sightlines_tlsh_df7e884a_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-df7e884a"
        date = "2026-11-04"
        campaign = "tlsh-df7e884a"
        family = "silentnet"
        hash = "03fd9782e148b2131f7845f6a44ce3fead1503cbb6b730499236f2646d1345a3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-df7e884a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dev/krypton/native/x86_64-windowsPK" ascii
        $s1 = "assets/minecraft/shaders/post-process/PK" ascii
        $s2 = "dev/krypton/native/x86_64-windows<" ascii
        $s3 = "assets/krypton/shaders/post-process/PK" ascii
        $s4 = "krypton-render.mixins.jsonPK" ascii
        $s5 = "assets/minecraft/shaders/PK" ascii
        $s6 = "dev/krypton/diddy/mixin/PK" ascii
        $s7 = "assets/krypton/shaders/PK" ascii
        $s8 = "assets/krypton/fonts/PK" ascii
        $s9 = "dev/krypton/xative/PK" ascii
        $s10 = "javazoom/jl/decoder/PK" ascii
        $s11 = "dev/krypton/native/PK" ascii
    condition:
        filesize < 11806636 and 12 of them
}
