rule Sightlines_tlsh_bc3e76e6_purelogsstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bc3e76e6"
        date = "2026-11-27"
        campaign = "tlsh-bc3e76e6"
        family = "purelogsstealer"
        hash = "89649ab108f8f5e611b72151b12563378bac75a10d9824796659476f49efb2db"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bc3e76e6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "s7oqN6v5ut941ay95UL9hfYWldNLBWpLRNtcLyRmStKqBbIs+raMCDk6? ? ? +4eL0w0JHOi4eVaqTFucUqzH2QgznF2uGDO43P" ascii
        $s1 = "/BZe1cFoQTjO4UHdFBRg3wD7b5Qxytw95GeTEOw0ku68Oth+nDSohWqBL9LGPGq? ? ? mMguNiJtQCdpHIkCvpryEhN5/LrgEXo" ascii
        $s2 = "c99sBJEeQ5tSUWMw3fWoaRjWYIdPw5Zu8omuem6cVikMqYQEfFXo+mB12y16OlgdZqPXtqjlU/2Givn8v0DzvFGdoC7JTPtsLV2k" ascii
        $s3 = "? 5rUVYtpnhg6QaP4mvg9U? ? ? 1swnqOt2EGOiko3DTBtxQsPOfYYMmyeHRyK7KXlNcNXvJdBpp/SyZmkqWY2TpMI5WCpo0gws" ascii
        $s4 = "y4Jzqs5/k6jxn/GGhnD+eIqZQ7jsMJoEbtv? ? ? GpSi8WKXVBLbgZhBz+dfx8ku/RXYmaMamFMp9OYtlVw6eerCEj4Z7osMk4Y" ascii
        $s5 = "Xt92OvtKycEgW9eIrFgpSdsU9upP6BfJ? ? ? bujr8z1+ebuCYVckDloksRgdE+Q4CmJ4mwbq1rGzdZ0EGFMxxW0QIkVZ7XL4? " ascii
        $s6 = "GONo4rQzP58jyXPJzzYJ6LjlBu2x? ? ? TuREl6WdwDhpGeimtDk+9b9UkLaET0RwbsfQpCV0EoZOxtBzLaFTMPQ/GNrOEnoHht" ascii
        $s7 = "gjfc? ? ? ndWRNctrbP8BSYiBgjaktM/GQLEssLslqKHEU+jm7eKl8odVNB5g4a49SLgXcauFlx0MnyH2VkKDn2/6CqKQveo5YT" ascii
        $s8 = "  'Ss? ? ? h/HoZ9jiZbq6lP+B7ly4ZCSJBlyud4mwUttjkEvr+CzTDgOVnLFhumn1ZDFXWo/S/KcIzIpLNBs/19a+N/QaG0dNO" ascii
        $s9 = "2ZZvoo8dv3OemhBrVOn0Kj+1b6Iz30nXnXyL/t? ? ? wOFPPeWaOffqdrtW+wDISSjt57o1o7s6LRrslYGsMcie2eETPMQqxEeN" ascii
        $s10 = "5KqlxpphHcBWwoyvR9tTOsPssdmbZfbzs/L1pEJ05fe9706QTxX69Tcj0axuJ2taMhZzTuF3N2EqG6yW4oS+s6sD7i1V9i/+k9Dn" ascii
        $s11 = "4jLiqz6JrcF48gGYqX5LED7qozDOPz+eUirmaI1oKualpEbhtRHOb06USPgqMj7/1p+hx67sd? ? ? w1jv4SWTLRSFeFx7DB9qk" ascii
    condition:
        filesize < 3296600 and 12 of them
}
