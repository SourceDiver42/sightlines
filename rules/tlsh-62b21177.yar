rule Sightlines_tlsh_62b21177_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-62b21177"
        date = "2026-10-16"
        campaign = "tlsh-62b21177"
        family = ""
        hash = "a2ac7069a0da876d52fa1d031ee1b4e4ccd5323014dab36507eee3f6eb7a60c7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-62b21177.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LnJcHBwkOKam8Ve0tMdzxsZRl+joI8vd3XyhdHSc6B8fIT5LS92Wvb3cYYuLhg2KioUPcHCQ4D4+Qny1tcRxZmaqzEhI2JADAwUG" ascii
        $s1 = "89xxbN66x/ruvbBAv7Qp1o+zXnUa18DjKtC3WXvZLs9L3lleVmHJyGZmvnI3byfkB2hQR5IMztGiC7lr8wIg/cMFVwjODdqe/gqt" ascii
        $s2 = "olcYZ0I+ZA7OXBJ4hxe5wboGy8Km/rqFhCRYxW3enbF1jTnAMT2CulFzXNs+pJmqd6fWlDpk96PyX+JvBrUbqiaW+pA12ltTS9WV" ascii
        $s3 = "eoMlvSEJ3PkTkdH2L6l8c0cylAFH9SKB5eU63NrCNzR2tcin3fOaRmFEqQ4D0A8+x8jsQR51pJnNOOIvDuo7obuAMjGzPhg4i1RO" ascii
        $s4 = "iZ8lgHBvzp6jGx2bGtwR6DJfezZuEPmUhX8C+gbBG08bXNjIQLOX9qF/bnOAmdzfk6Wt6qPTpDHo3slTmmgitKmK7Iah5NV0rJWc" ascii
        $s5 = "/E9i+/BIAgHTvndqQMqa6boMwCsR9pvuJDrYhhjQ6OvLOCz1mYMUewwgvlD0h4NBddjR3Utzs5KP5hxycPV89iM6tF/f3qZaWOwT" ascii
        $s6 = "vXMtBEQKeW2kPnKWyuLpaSONh0HqVgNB8XUGHfwA/HmHtx7dltG6RcWbb+j7selPdYPwxV3hClg34/LB4qZTJWCxMfFy3iED0wnB" ascii
        $s7 = "zp6jGx2bGtwR6DJfezZuEPmUhX8C+gbBG08bXNjIQLOX9qF/bnOAmdzfk6Wt6qPTpDHo3slTmmgitKmK7Iah5NV0rJWc5WzwFZYN" ascii
        $s8 = "wlAMk5US2R1WaIvn1Llxjxa0s4ofjYnciIROGhdqtrXBkXT0wC7ul/lmTSiONgCxenWK1H84dww+2pSVjIfLUWgG/yfZvP/GQYD9" ascii
        $s9 = "a+RZWFmkvG/I5A4W2zIbeNQdqwv1Rjzra/UljB0AE91ZCxS7NsBr/o0DAIwHKsfkx3s8Phtk1ynDa0AugsZrViggYRO1u9chITGc" ascii
        $s10 = "4bsMIHsXGCsfUmRqyD5zAnbYZAiK2Qb6L/Fr7tIaJtLjzp1hJUrglIwe1zMJ24yu9avH5OGmhQ+Xs30MBl1XceqKCu/bWASF++xk" ascii
        $s11 = "8CUlb0ouLnJcHBwkOKam8Ve0tMdzxsZRl+joI8vd3XyhdHSc6B8fIT5LS92Wvb3cYYuLhg2KioUPcHCQ4D4+Qny1tcRxZmaqzEhI" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 30998528 and 12 of them
}
