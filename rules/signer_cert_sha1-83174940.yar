rule Sightlines_signer_cert_sha1_83174940_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-83174940"
        date = "2026-11-18"
        campaign = "signer_cert_sha1-83174940"
        family = ""
        hash = "262a24afffa5b50f3ce7f8c26929f8b4042c93b6a30b7612ad59216d935963c1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-83174940.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FzV/k6Ll6RP9GJqo9TqdehFQ+xOx/cy7TyZGV1wcyyl4P6z80Q5nOrPwEwjNnbp3qMxv0SDVna1YzWVKH2OhJlQQtmwl2XBnPgmR" wide
        $s1 = "O8Fy0iDpEAO2bsCAWHemj640lsBFBDDxm15Rwa8fiIhqKXtCflMUZsCzEIEWT40vuNIaVBS/kzF6ARN3tPdPFej0h6jujsteQ7Zu" wide
        $s2 = "fs+lqjhjj6VHCcNLfsxY6zjiNreAK6NNk1pvyJwiZl5ME/oIZxQC1pJ+MXWRdOOPdaFMpK0bT0IOpdS6qi7vM8AYze12Qv6+IBtZ" wide
        $s3 = "OibaoCq7ySLgTvqFHWO5G6uKCF3pR5EXVEV1JTZ4EWcgOCULqzYKu6MluBhQnwg40Gngris1ZyvXCc0vFU8O8YWJv8mBeiGxPkJp" wide
        $s4 = "0l/AySizHrerEUjZYyvtwwN1v9CrbqnPnlmo/GGuZtwM3Wo4YVPDBkLekDtgzpfMrX/Udj25LLeR0LSkm0L9pjgg5hdNozzNsWai" wide
        $s5 = "7NOdN0r53sKmaJ5cPJAzlC9N3bPcWr70s9p74Gv8YhzdkmWHaF4c2rMxhy2J0AH9vutvrdjTLA8s8KCSjvv/E+wWvkco/BLMepgU" wide
        $s6 = "mwrR/BORo5sp28s5Nxqyg1149VXp3OSIWVbXjXHv6N8F/WohPTCoVIEJYBFgeuIMcWgNEj7R58KyHXsDwTzxbwZWlZ1cXM4x7ViW" wide
        $s7 = "9jl8FoO8HvG79daX6c2uUpw+/7JmDhrWcENIT+5qdkz+nNEjT45M9n51W4vHhXi/h8MYIYLEwhnLubO1rtVwky1gxTI5l+cqhUny" wide
        $s8 = "cm3y0RBrqkRzFpUBOj+lZxE8BElXmMWT41OePUz2XJo5e+ijgDBNmYhTeUaPG0ZZ9cPdA1cMFkvq9Tg7t5l/qDCAgrOh1d9hr5qD" wide
        $s9 = "w4NyiiqvzTLziLx1L7Hgb7eTl1mxRrTHC8g6gfisSa4fpGibhGvjd+Oj2508QOjMWPJDpUmDTTMWu+7DPxEeTZ69iQcoO+4nczp4" wide
        $s10 = "YoFxqRaZmyA6IitJ6c6sboqYJYxKOjFgXxtfJMqqnZz9V/ILKzwTzlShLrY/YetJdID1lSSwAZPj1qvEIT1uNTMSzI2Tgd42RR83" wide
        $s11 = "lcnD6EU9A9zFAd2MjDANBgkqhkiG9w0BAQsFAAOCAgEAgNBDBa/87l8mo3eU0/3GxbQ/Our7vRKiN26Fln1vnPUyvXnpvddpszyG" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2176800 and 12 of them
}
