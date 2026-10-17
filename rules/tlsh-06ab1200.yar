rule Sightlines_tlsh_06ab1200_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-06ab1200"
        date = "2026-10-15"
        campaign = "tlsh-06ab1200"
        family = ""
        hash = "4dcba7f07c31f2d0410ea3efb2f067c1ccf24b8318012514302fcc65ec06b30d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-06ab1200.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    return BROWSER_ICONS.get(browser_name, \"https://media.discordapp.net/attachments/140263598965404" ascii
        $s1 = "        ps = f\"Add-Type -AssemblyName System.Security;$b=[Convert]::FromBase64String('{b64}');$p=[Sy" ascii
        $s2 = "    \"BUG_HUNTER_LEVEL_2\": {\"value\": 16384, \"emoji\": EMOJIS[\"bughuntergold\"], \"rare\": True}," ascii
        $s3 = "/v0002/?key=440D7F4D810EF9298D25EDDF37C1F902&steamids={account}\", timeout=5)" ascii
        $s4 = "    \"EARLY_BOT_DEVELOPER\": {\"value\": 131072, \"emoji\": EMOJIS[\"early_verified_bot_developer\"], \"rare\"" ascii
        $s5 = "    \"ACTIVE_DEVELOPER\": {\"value\": 4194304, \"emoji\": EMOJIS[\"active_developer\"], \"rare\": False}" ascii
        $s6 = "    \"HYPESQUAD_EVENTS\": {\"value\": 4, \"emoji\": EMOJIS[\"hypesquad_events\"], \"rare\": True}," ascii
        $s7 = "    \"CERTIFIED_MODERATOR\": {\"value\": 262144, \"emoji\": EMOJIS[\"moderatorprogramsalumni\"], \"rare\": Tru" ascii
        $s8 = "    \"HOUSE_BRILLIANCE\": {\"value\": 128, \"emoji\": EMOJIS[\"brilliance\"], \"rare\": False}," ascii
        $s9 = "SKIBIDI_INJ = \"https://pomf2.lain.la/f/hxdmhotz.txt\" # injection url dual hook de" ascii
        $s10 = "1080&screen_width=1920&tz_name=Europe%2FBerlin&webcast_language=de-DE\"" ascii
        $s11 = "    \"EARLY_SUPPORTER\": {\"value\": 512, \"emoji\": EMOJIS[\"early_supporter\"], \"rare\": True}," ascii
    condition:
        filesize < 1048576 and 11 of them
}
