rule Sightlines_tlsh_0991087f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0991087f"
        date = "2026-11-19"
        campaign = "tlsh-0991087f"
        family = ""
        hash = "0264d6c72f04bf67145e1ce99872332177429724ae7051045186b73a79f14f4c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0991087f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAB95qPZOYfNijmHzYo" ascii
        $s1 = "fqQ9meJkAZplhBWYEXA9mNd0AZvNDD2Z5YQVmR2oQZutjEGathwRmWEUBZmLhAGZbDRBmw0kPZuYwEWbByBBmnh0RZpgOBGb11wF" ascii
        $s2 = "miIMDZrzIDmaHaRBm1sUQZjRdD2YARgFm72AQZlHiAGbU2QFmJ2cFZtRoEGbTpw9m0iARZrUKD2Yp2w5mFRkRZj7aAWZt1wFmrw4" ascii
        $s3 = "mBUoPZjfZAWZadQFmRg8EZvTaDmbyDgRmIyUBZp8ZEWZs1AFm4tgBZheIBGbawhBmFUUBZlY1D2YQlwRmet0OZvXZAWbJ4wNmnBU" ascii
        $s4 = "PZsLpBWZarg9moNQOZjoWBGa7xA5mIzEPZjTIDmaoxhBmI6MAZu3uD2azaAVmXygEZg3UDmalPw9mwicEZmPcDmZO3Q5mOsgEZoe" ascii
        $s5 = "nD2b3FBFmYmYFZrgVAWZlRAFmUi8RZvvaDmYYaRBmGocEZgDEEGZnyBBmYtkBZrGGBGYdMg9mS9kBZmriDmZy2AFmH6gPZoTZAWY" ascii
        $s6 = "ATABFAEMAVAAgACoAIABGAFIATwBNACAAVwBpAG4AMwAyAF8ATwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0AAABDAGEAcAB" ascii
        $s7 = "AaABvAHIALAAgAGMANAByAGUAYwBpAHAAaQBlAG4AdABzACAAIABGAFIATwBNACAAbQBlAHMAcwBhAGcAZQBzAFQAZQB4AHQAXwB" ascii
        $s8 = "gAHYAYQBsAHUAZQAgACAARgBSAE8ATQAgAGkAZABlAG4AdABpAHQAaQBlAHMAAABwAAAAUwBFAEwARQBDAFQAIABjADMAYQB1AHQ" ascii
        $s9 = "AAAAAAQAAAAAAAAIAAAAAAAAACAAAAFQAZQBtAHAAAAAAAAQAAAAuAC4AAAAAAIa/Myk2e9IRsg4AwE+YPmACAAAAewAAAAIAAAB" ascii
        $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEDLEGYyxRBmchYRZgOIBGYSrw9" ascii
    condition:
        filesize < 1617458 and 3 of them
}
