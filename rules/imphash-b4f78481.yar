rule Sightlines_imphash_b4f78481_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b4f78481"
        date = "2026-11-23"
        campaign = "imphash-b4f78481"
        family = ""
        hash = "35c30e83ec1387dbcf7672138941a7e6039fa8e34ec31af7cd020f82a2e9f75a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b4f78481.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "houhdiM5hE2Q6BF0MMlUxhXJ8avPKWwe50rsEmnjiGcLkV3Na_LdJjeGZ1EsR2JHgxfX8AYI3fEWbtCAkHtTg1LYb2qeYLF_S2OQ" ascii
        $s1 = "M9KoAI-_oRrqI4CvpGVdUvfJBoGeqef7Esfnn21o6iiz40syWtPljIY_z08OS8qGQhmEax5LKxxk7qOPcFswgKnGVHsQYxXzl3Rx" ascii
        $s2 = "truedKwtpivZTYiQR4-jP7rJW-D8i1LOK7lkOSJrV6UFxDCvy9sM822NcP0Ggm-R4meB9PFHXNX5sqwT10AYr9IiwYZOa-vK69EC" ascii
        $s3 = "u7N0iTOVb15ErBD3KNcNUPYfJ52HN066eaT5UtWQZBvICA9DrzAYN_gnIdYKGy42MhEEbiR4u3TMjSyttwiL7lyqrS-VOZQeznc5" ascii
        $s4 = "fluostirrysERWkis-WMmsZ4QEP240bEpz0eVvyOwDCHQu5kzjihfImitXs-AOoTYEZcUH1LNIw2qKS3L8Zno79WbijJtWXWlS_a" ascii
        $s5 = "4CqjEOG0JURg0wvMRPj_D-aX7Le-2zSpihxWScfXO2oVo_t2jGxCl9d7UrUAHTA2JZ2kpKyFsxhz3iLNq10jCrRuZx05HozbD-ib" ascii
        $s6 = "_qAEz-KnrIpKFtXZOcVGvK26pBsHCN79E77ra4ojXGoKHGa7yxtfPPJ7g99ReUDFYcmJhqvwWkOZ3yYP1JOWDlne0iWSXUtkmNO2" ascii
        $s7 = "Jep6wHUPlCXmN_FAEd8WfqQ4q_FcM3l6ZraBAupKKZJBkeq-hmxsJTC2ALcjoPLXReWlglybw9waAtFWsEGjp89MRzVERNI53xmU" ascii
        $s8 = "M0yqgKnbBe2qxS3zOubaHcoTBmb_4c8AWiNz5xSeeM78j1zg1K9IKBvcBXwGfcRdUjNFcVNerkoV6wyA95uRyU0t3IsQwl7cZTFh" ascii
        $s9 = "siqASoKKKQLbcP0yza5jwRHFEu_jCWkqERi_dt8KZq4g4AOkXrUcHaTDGqP7JmlDNL2Ibq605H1ZbX-QhDB31ZHQr6JbMkajkupL" ascii
        $s10 = "yNctNTBNIvXCYvmg7zKdm8MjsMDCpXDPbt-WvVGzVKhECIB_Sk1mTQiHuc9Krn5tpgAx3_swdvtl4geuUqcAptfDyESFUKix4sZA" ascii
        $s11 = "qW-iaTtBd9OX0euHJXGr-fYuWlmtgcrJJHeloeCTEFv01cZNwi0wasRU51CDAtUWWLi8hy6Z8y4kI-Jz0tAMD_Ov_hxN6pF9c1Sh" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1261568 and 12 of them
}
