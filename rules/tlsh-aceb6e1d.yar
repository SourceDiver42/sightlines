rule Sightlines_tlsh_aceb6e1d_zigclipper
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aceb6e1d"
        date = "2026-11-05"
        campaign = "tlsh-aceb6e1d"
        family = "zigclipper"
        hash = "08f36297e916e15853dcd5c4728f2ad554eda6686e4342867f4653b982d260df"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aceb6e1d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        elseif ([long]$v -ge 0x10000 -and [long]$v -le 0x10FFFF) { $r += [System.Char]::ConvertFromU" ascii
        $s1 = "        elseif ([long]$v -ge 0x10000 -and [long]$v -le 0x10FFFF) { $r = [System.Char]::ConvertFromUt" ascii
        $s2 = "return $r" ascii
        $s3 = " break }" ascii
    condition:
        filesize < 1048576 and 4 of them
}
