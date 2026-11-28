rule Sightlines_imphash_40ec9ddf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-40ec9ddf"
        date = "2026-11-09"
        campaign = "imphash-40ec9ddf"
        family = ""
        hash = "2a4787ece04ee9284f7628df4e899d6869ea9abe7b3b636453776790d04e56ad"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-40ec9ddf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "e4MS/imhGryQBZYr25zDObPBoVjkBTSKHnggCrbAgvuJ0aDsQ6RxTqMWVMD9/xoJ" ascii
        $s1 = "gn45gM23JSn+7DBtjX18dxFlOWxk6xJRyJ8PvHnB/Y0CAwEAAaNjMGEwHQYDVR0O" ascii
        $s2 = "0bAKpaVOwb5bNsxZey4jcyZWOkzHgdhPUcy2O4MNS4ZtIqnayXFu7+wS3CUFQKiS" ascii
        $s3 = "6b3xZ9SZ2/7kJH8zb8Ay1jRcnsOyLz7AQM0xrSpNcD4XPx+37XKLHj+elAEay/aU" ascii
        $s4 = "+sDrcCMi0DnIYufKxgQpVsrrtOwveZSPw/bKmxIL/t8yYQD96VnUat+bT5cJd+ae" ascii
        $s5 = "sWIoe0+dnlHRdk8rmPEwuxrJi2ejtrWRkZpwcbvdnizCYOaOp4/vlt0u4du6YLCV" ascii
        $s6 = "hXUUw/L05Wg+mSPEvrWffDVnP7ygcq+Vx6kbFpiSNRVkgnlbnwApR/87nKL0z+1w" ascii
        $s7 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s8 = "dHJvbmljIFRlYW0sIEluYy4xETAPBgNVBAsMCEZsZXhpSHViMRkwFwYDVQQDDBBG" ascii
        $s9 = "urPXbrqd5PV9j7KFysmM+b4O6f5liQEBf82sVA+rPUtQw+l7Dm+tMrVTGjet8SdP" ascii
        $s10 = "SIb3DQEBCwUAA4IBAQCPu1nBnH4Lzux8R4qJk6+6VjHgym16qTgV6RZvze/wH8zQ" ascii
        $s11 = "GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 25754896 and 12 of them
}
