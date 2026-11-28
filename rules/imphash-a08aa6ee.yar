rule Sightlines_imphash_a08aa6ee_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a08aa6ee"
        date = "2026-11-19"
        campaign = "imphash-a08aa6ee"
        family = ""
        hash = "39d395fd562a5634ad19fe58e04a9e07b21857e8fd605f8b43289debd3a5832b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a08aa6ee.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "YvfTCs5EmAdQs-Lyuz1UBmwIBwZw9P1AwHAHZvouj27eFJaPqDXNlnPBDRctwfMEWxo-O48lwiPhiipG_bwekQnKJNG3dYzW2uK8" ascii
        $s1 = "qQkRVht5tF1jVBgGH6ZPmPrYYi-IfByNv81Wr4NPFSMd1nCbrmUcDTIucX4HdJK7bzPbWqHAzkj3ph2QXeBwDgjlh7KaHHazZEJv" ascii
        $s2 = "gZvcZXlpxr4iTZ-hC-TzaKfCaTHG4To1YzO_8dzO-IFlHSFLwNRemkPI_-UVVtJsNhBmPnlcwM7w5oUKgp9S47b0q5jajcioHR2B" ascii
        $s3 = "vmkUBkCafZtDajYEejjZFEW73fqLNRmigQGKQuCMlkjo5Az5HC6mQdqxuhUAv2AckSgJn-KAJRLIlqeb2x-I8f0s1dOLPKcL8NX7" ascii
        $s4 = "t-XzA_IjwPOHOXY9BzOdN3B_sur_rFiWwrgtUHKSmvgdMmBGbg212s04p6Z5SVjZcl3s6yezpHobA1uDspnOF8dJ1hEklHJPtQQ0" ascii
        $s5 = "UT73p7H5WLeznYdayCN-_8GkpGTjKhXHVkN2siPxgVv5v4e4hEQFaSK3XFtU1R69RMz2SrpkSQOxP-10cJ0iCvzVMdynpn-ml1U1" ascii
        $s6 = "PD23hPiWIzsNtm0dcdbe3lxwPUWxnbKG7cr3zjRAiKE8RpCJ8IBV1Vhi8c4Mc6OS9ycxmZM5pbO_-UTRhVc_MuqnBoY-eWBQyYrS" ascii
        $s7 = "Fzxe58CotZkT7hW6jP1oeEozs9_W30J32zFmzBaoNUhtX4NEuZDRp8eGJg6Y4wEMSOsLLrbXyRUvHK1291M6O6v-qR4kyzcrkvFe" ascii
        $s8 = "eustBy55Go-SFPtl8kjj8QYlJi1WgxJh-GdOSaUivWJ57HkIvuOALrxPCyeIXhRA4sliDmvXtPgqfZye4NDYKTZyE3q3VoVhSt9G" ascii
        $s9 = "Sjre9UusO_HAvyaSWzoHrPIAr6bVGc14xgle8liKQwPdAeP7ezSXRBlw|hGMOYxZ0PVj8ej1Yt82K5tK3aMldf21WbEv7BokZq61" ascii
        $s10 = "rkTyOY0CQetDSgFKqbFWhhVV53h_fFiM3V3E2Ugd9_LA02XXMlxnHf5BpJjf10iGy5ZTyx6_vZTxL7SXGDklmcX4dWQzfgB3OwQH" ascii
        $s11 = "nWOBGt_gmsjyjki6c7EY1bP5eoixDmT9kriedyuias0gIG8iaCnoWEOXeLqb45jwPw2Y_CaWhavJ3pwjPRHuVrjdHUqljnsTIMCF" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1256448 and 12 of them
}
