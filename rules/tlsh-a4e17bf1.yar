rule Sightlines_tlsh_a4e17bf1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a4e17bf1"
        date = "2026-11-10"
        campaign = "tlsh-a4e17bf1"
        family = ""
        hash = "0d347e1eab172e220c10ca0a00c610fe7f8bf0f484cfde088a46b0a1fb812e23"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a4e17bf1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Overlap of {0} day(s) between {1} and {2} from {3:MMM dd} to {4:MMM dd} (severity {5})." wide
        $s1 = "Window OPEN for {0}. Complete before {1:MMM dd}." wide
        $s2 = "Pruning window for {0} closed on {1:MMM dd}. Late trimming risks plant damage." wide
        $s3 = "Industry benchmark dwarf apple rootstock. Highly precocious, heavy cropping, requires permanent supp" wide
        $s4 = "Within Prunus dulcis union; GF677 almond-peach hybrids accept almond scions reliably." wide
        $s5 = "Later by {0} day(s); verify the species allows late trimming." wide
        $s6 = "SpeciesCode,SpeciesName,BotanicalName,PruningMethod,StartMonth,StartDay,EndMonth,EndDay,WindowNotes," wide
        $s7 = "TaskId,SpeciesCode,SpeciesName,WindowStart,WindowEnd,Status,Zone,Method,CuttingDepth" wide
        $s8 = "Earlier by {0} day(s); confirm frost risk is acceptable." wide
        $s9 = "Pyrus pyrifolia is widely reported as incompatible with Cydonia; the lookup applies a strict FAIL." wide
        $s10 = "Reliable semi-vigorous plum rootstock, good for heavy cropping cultivars." wide
        $s11 = "Within-species Pyrus communis union; reliable, vigorous and long-lived." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3320832 and 12 of them
}
