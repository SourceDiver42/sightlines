rule Sightlines_imphash_cacf7bec_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cacf7bec"
        date = "2026-11-26"
        campaign = "imphash-cacf7bec"
        family = ""
        hash = "01a4fd8693bff2d10204e994b6bb3e7cbdea20a18e8421ada9c7e25806be64b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cacf7bec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "x2Z9Oq5y3yA_5ZuBBZX-YWKoDYjFRXubd0GLILn2cGkcmMgxI_UQJagRsokhHJKNpBSBv6wJMWXb7fTWzFE5RdfrQ65QeV-E5_tz" ascii
        $s1 = "VwqAlxIrsHUJGJtnyrlq48U3SC_16ym0SABgRt13KKNerwh17uSVGbwUvtExcBa2YhD-MGPov7qfhpF7spldZ7ANOEOknFYzX0xj" ascii
        $s2 = "xyBTRcbdeLzcy-f8SI7d_a1MEKyqSA7QYL8lExBIAtdx0YRVe63lh1SW5F35rrzakGqLfwJJOpgcZGX9WG2mONG8ACnoaWEswngu" ascii
        $s3 = "unEWfNIiDTpmltYzXR6SbXouOL54UmVIPUd31fkxbecaWhIMI6w7VQLXFgI_i63RfCjgKgOhNnsS8YaBA-lYHi3Hv5psnPqepqu4" ascii
        $s4 = "@?>F7Z45gwQHhoBmNaxRVGbJj2D8QDFfjWwCqUGsC1TBKE-pqiuupXrDPXhPEpdsk1mVA2LMcPCQbZExzwLu76NWvUXWuo96Kb12" ascii
        $s5 = "jZNBxyKg0HS25Lgz37E4LoFnJqM9LYbU21GvdOi2_WRwTaaSN2nE7HagLGECvS8P6ZvdWrYAhxaRtR15fR_-JsiJV-XM-xpfHODb" ascii
        $s6 = "9nCVUo6hu30MFR8ZE4Jp51G_vn6Ca1te-zWHZGdw_ZiOF2wQjTxxdeCsbQNecLv2ofN4WhTdHIVb2F_yLu-0J8CCUqkfqY8sQ96B" ascii
        $s7 = "1qveEH8Zou6rpXDZUiSCzKZFNAnov-SRk2fYXEd9q7_Se07jyUd4rv3nwBtQdPVdSC9BtlxLUa84pLaX5aR40PsOzZogtIZ_CgV4" ascii
        $s8 = "9fsVmLpvf7MpJXIlPbUEU-T0voN0uq0qxDjdTPskaH4R9i9teYRFYInAs6uR5_CWOpN93m3EhEZztjbWw69exkMka__4lT72o6fO" ascii
        $s9 = "GjH1dkDCl5Gz-pCHdOc9gwU3NZtQ6rpC7w0SXILhfu_4hONv49vzoI0iKN3yviLpt4Eb1anE-uBkctKQeaJRfVZlcUpPCtokBMjt" ascii
        $s10 = "4vbP-w1xh6RIlfw5chx36dxgoTO9-7Ck_HF-KcZDe3PWC86zXJsRVDWRAE3T8dvNkwyDhWtmNxnjhSB3VSBa4RkHb0SspjCJLb4Q" ascii
        $s11 = "9fIC8mpvVz-DGN0nM1UtrueI75BEJ4RgOqxttu10odwC0trO5mPu_poAAxhiLSQx5Z2RLc2ttAUP3MnFkjQEf6Cx1SIFjM6qhave" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1490944 and 12 of them
}
