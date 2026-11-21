rule Sightlines_tlsh_ef8238e5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ef8238e5"
        date = "2026-11-13"
        campaign = "tlsh-ef8238e5"
        family = ""
        hash = "5c0d45a3a32e88be503d9176574c95cfc3f569cedc756e96432ecb35d3074606"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ef8238e5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3FKY3j+[char][int]$OqV8uvnKXXFmiWArD);$p1L5G5IGJdoRwxkoLAgjZ9=($pT2p4PPstuzqwqViFYkKWDbQ -f $CFZ2T4a" ascii
        $s1 = "VPDvHpUASiLSuE23P)-eq 0){$jp9ijrAyXLqkOnY0=([type]$KG4Hx67DcgT0qf7xg3)::($CQt0mPqC9ZssMW5cvVS8)($fal" ascii
        $s2 = "K4c3vHmMlsMLz5ekw+[char][int]$meH2RQu3z);$eNG29N0SfpB7a3tBHXJCzb=($ZPYr3aqLRSe27DaW9ynb -f $B02LJMN3" ascii
        $s3 = "YzI2fI=($NJcki6ceTVvp3OuSfhT -as [type])::($TG2dEO6nETfFpCIC7tnwxc6i)($EcZ0bEPrFNdbvy3WqM9LYyQ.($pek" ascii
        $s4 = "   $EcZ0bEPrFNdbvy3WqM9LYyQ=($pV2B20HxynKT4LQTqF3b -as [Type])::($b5Q8SFnJtRCtNZ);$ck3H7ilTXZLhqrPrQ" ascii
        $s5 = "1F1uiTrwMt -lt $ck3H7ilTXZLhqrPrQYzI2fI.($noay0oxOenkN85z1HUfSE)){$cp46y621AzmojzH=$ck3H7ilTXZLhqrPr" ascii
        $s6 = "- ($tWLo0YmoOZyKHK[$Asy15GnpHU4FAwzarTcD])) * 12) % 31); $f8Nj3eD5DwhvACaL += [char]$DER0MBmxFi };$p" ascii
        $s7 = "$RuR0qrcXR8SVjI76io3M2jg = ([char][int]$Mq28B1ZO1BHQxewu093bQ04 + [char][int]$Zm7T6PbePsSfLrjwJpYT9E" ascii
        $s8 = "$If36QG5RZ7UXYO0JZVcMP8n = ((($FaVa9IlwdKmC3xRO4isv+41)-($sWpLR2NIUtEFQKp3boi0bhwU)+($sWpLR2NIUtEFQK" ascii
        $s9 = "kIMkhn7g9PcYo0lTADG * 211 + $fjY40xFrEpeVT51 };$Ck7gfUscOSQqNw1yNf4EZTS=\"\";while ($frW3XkIMkhn7g9PcY" ascii
        $s10 = "$PTRs31ENwrRGIw = ([char][int]$aUZ5nM0iMbVEH9UCkJ8ml4q + [char][int]$KLIUJ4vAQLYCIKdMO17Xjn)" ascii
        $s11 = "$z1Ab0PpaTEWP5ZHVt = ((($e8Kd0TexjRUX784qy9id3Bn6+24)-($sMr5PQGUPvYNhlnhHLrglQs)+($sMr5PQGUPvYNhlnhH" ascii
    condition:
        filesize < 13373926 and 12 of them
}
