rule Sightlines_tlsh_8d56894b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8d56894b"
        date = "2026-10-15"
        campaign = "tlsh-8d56894b"
        family = ""
        hash = "045246d3f90019498bec9b92b1d42a057906049ca5313a47c6f5262eff7801a9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8d56894b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[{Fore.WHITE}~/{system_text}/{pc_name}{Fore.GREEN}]" ascii
        $s1 = "{Fore.WHITE}$ {Style.RESET_ALL}\"\"\")" ascii
        $s2 = "({Fore.WHITE}{username}{Fore.GREEN})" ascii
        $s3 = "from config.settings import *" ascii
    condition:
        filesize < 1048576 and 4 of them
}
