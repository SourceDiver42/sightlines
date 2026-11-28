rule Sightlines_imphash_ac9efd7f_phorpiex
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ac9efd7f"
        date = "2026-11-26"
        campaign = "imphash-ac9efd7f"
        family = "phorpiex"
        hash = "2b4098a38f150416a1b2064ffa82982e6ce2d836b9ef9d906d55a9e66d3a87bd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ac9efd7f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "4AtjkCVKbtEC3UEN77SQHuH9i1XkzNiRi5VCbA2XGsJh46nJSXfGQn4GjLuupCqmC57Lo7LvKmFUyRfhtJSvKvuw3h9ReKK" ascii
        $s1 = "FIO8DeiD8sv7xkoaNJn417jH82j3B6mEzsuStYQVKoWZRmyrH6vg3" ascii
        $s2 = "4vRoYtaoPKVZC1pibvZg7TK5KuXLkpV2hF3DsGyS9SM2" ascii
        $s3 = "B62qpDfv86fUZc4ntrYJL6eFJZajjNKRcBuW5iPbcLNkiPekLkV8NdA" ascii
        $s4 = "Cz6xMbBst86mjM44qAaE5ahkD3F8JpLY7LFGHMiKYzwS6mn" ascii
        $s5 = "dgwkBeATk5ut9wopqzSyBhE1MtsH3ZLUVqA4L16jYGE" ascii
        $s6 = "UQBrVPgsMh_86kj2J7v7MuchOVg3wbd0eHv7MdwKfMZ-06my" ascii
        $s7 = "ress xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/></SOAP-ENV:Body></SOAP-ENV:Envelope>" ascii
        $s8 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:GetExternalIPAdd" ascii
        $s9 = "Gwnp9rNZX3L5yWRUHpAX2t7q847dyFNL5vxh9QB1pHz1" ascii
        $s10 = "B3pgNBJ8YPZ7wLV91cf3Gy8acPUr3mn2YVW4SgMeH5rw" ascii
        $s11 = "CTHeb62DyfeWn4wPCwTgk29SJdrKqEFjr1jzuQmQnUCE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
