rule Sightlines_imphash_c41a9aaa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c41a9aaa"
        date = "2026-11-26"
        campaign = "imphash-c41a9aaa"
        family = ""
        hash = "07a9004fc9dc823dbd42ad3d2ac4bf3a896e7692f74411b340fd26f6dfcf9a52"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c41a9aaa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Jm_P56vqaj94bEuxwpJnbP7O5W80VhYbBc8CD24Ii7Btlju6NBa5AY3YT2kg-6xXqdrSo3M1dXQBRwSLnpZW6Wk-Tf_mR0FmX95w" ascii
        $s1 = "ZF-MwF64zyFv_OnRWphl2khiBUYmRS_DgBJ4r31AYcHDyOIT3axd3ASKNTRLOsj6XcemGVw4fAkVL9acI29surrounding names" ascii
        $s2 = "gzJNI_5cjKued8xtRvXxgpWHCecnoyMQd4v1qAhqZoKeRMPU-Co9-52kFQ77976LE31fBJOj1VESQDjfpE1INWRNh4vqxVGJWpTw" ascii
        $s3 = "Mpkh9LiQxO8zW5dZrjgCU_y3znMTtMusg6LbKFwlaR-jBMxxY5l_LUCktn4IEK3ZNpFB_i6FpVkh8WfqR9wmSKHsE9X92oZGklYN" ascii
        $s4 = "kRyaBAyQ_z0dmVdzWmYowmCCqUQHfvpCo_R-6p92wOL6tTWmJXpNYIjZgcpHXGJTgDxximVFC95NshsBv7iPBzYL4pegrMJAjEBh" ascii
        $s5 = "ZhFy0oGqzhpr78HkYh2ORNXib9yINxVX42Gg6Vy3p9cAFujSdru5ePRMgd0e93RZqa4wABrsmnT1fT6oBZKQqfUz1opO56x3qZZ_" ascii
        $s6 = "2aN4xs9xnfw-852CGCVPWq1utBWhAy9Yx1mAemfcMqF5pv_vaARsUWtk-QJ0_PMHt0kh-4UISR64nrogjF1EQGc-SZ8Bkt7a66lq" ascii
        $s7 = "ApPTsb3unamXFn_YquiQJmF68Xr8Evo9gBIAz5hF1uBRORgYYXLZGkBbC0yxGRdJS6OEJCPP5ywhxtUFgGSKoV2PUOfvoTrgcHAw" ascii
        $s8 = "sSTiwZu2gR4jUOQb71nf69otzjikCNjjbD9ri0ySw1tHrV6CL8F3pfzHMHZfW3DArBY45PH7caXTRRvgPI6YzAZHyQUbmIvKc9E6" ascii
        $s9 = "BYPmeSAb5owOpceKxaW2kGjLzDuLD-q2U0Ith5NV30C0ECVzrl_83ZPMKBVAgU054IdCnxqhw2nN0bwqecyxdVzjMTsiAomaH10t" ascii
        $s10 = "Y5sXw1NgWIpdQGhUfMgvb8F7XgtaoAaJ7UuI1DI_4fwRCGtnTS19TI3nrQjsvpuo2u2OQ-gI5dehRsCcR2NP8wKEK0yiM9ejGYL9" ascii
        $s11 = "_Ej9CSCAi6gKkzsDnM1nISwtj9skHqB1uvCbZjbJh-f7Za_mCN7mCEOL5TirosWy3rvJY47SebUJXWvX703xZLRA2c0yymytnHmA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1439744 and 12 of them
}
