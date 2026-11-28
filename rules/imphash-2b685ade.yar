rule Sightlines_imphash_2b685ade_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2b685ade"
        date = "2026-11-21"
        campaign = "imphash-2b685ade"
        family = ""
        hash = "4c6d3482401a7cdc0140a038b9f28616ce2de9a85df0c47e1aab1798f6ed46b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2b685ade.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FdE5mvvTj1vROLf17RHx6pTfXWYuU9W2gulqGA0gE1kwmQrATMw3JNZPDx_Eo2XH6sNnK-Sdi_5Lwz49euN7tVFF-UFjxb0GtKH8" ascii
        $s1 = "5M-ggPohprRwzcDEAdIJfkstJGCZl2KjSxVFJNEddmdbNOvPikkxLpDQ0yxGpZG3TBTg1Ua\\Gh712CaQ1vBfasOls067_FvM2q9K" ascii
        $s2 = "9CUidIiq7HbSDpKBX5tkwgnKMewhm1zKXZT-bD52PJOlYSUfKrBsKVmYJonF3vkrgo0t4jEo8IlQlWS2q67UQmq_WZZYzQycMFq-" ascii
        $s3 = "oyIp_PlmdpZyX7RCRxVfJt-DAV28b_XswpMW361ZtToaB0jQRbsgtsAL3h4z6ljPV0EuMvbBT7vvKavYwtozMWFRc4qnGY0Yihrq" ascii
        $s4 = "GAm0yp6qpW64wkL9XULjafXFCN3vbZX7mW-hfQt_Y08sVXj2BtHiFTSHXzKIXfqAqjuq5qEZZfuwigJwr-MOPeaJVMAK31nipQZe" ascii
        $s5 = "jY_17x6xWpybEqnjDu39RT4L5PUDlECcaF8et6SSrk4vl4lII_VYz3e7zEsKyq9kffSGeFKy13SXgoRLOfTAhgvYF5TK0P-M8GiD" ascii
        $s6 = "v6BUuwFRr23rQeXhk2YupCVr_LaiW9p0tqyMYaEFpJN1VzeSbLfUzpWsT5Kvb2WJZaQJXxM4snhuG0qWroIuyNEQB0-3CyjRHlDC" ascii
        $s7 = "1cN8ZdGtMjaw0z77nLEvqO005ehRQQ1dI6PcO9E3RRVytFR-uxoj8raiW5t_dKToYkTvhDGEbls5xkZMcZ1hOAGaWn1o9AfnwHpX" ascii
        $s8 = "2IVgjjS3rztxhblQrVKHUtblq1e-ipxAwaclNF1j55CD0rZouHVklyNcr8Z2zW9BqA89hRgeTPYYA047gluyrXY_SAb92MJvaLmA" ascii
        $s9 = "7ztWGLDBOD_PeX0lJPcvNnPrg7MQQFH9kyPWbvjeXwdUNdXTLn-atWwAe_ypymV2T-YoUBY3QsbV_3yR8sc6_4uGfodZMFgOT8wt" ascii
        $s10 = "uNpblmMVRAighpFQ29YQ8cvtH73MEms3-u1hdxcFWbJYGVBF02P7dwSLIF4laHKtE8ITOf4-I*hAPvcr2TYN3nveNBeZ7Ey3rOx2" ascii
        $s11 = "X4A5s1Iqkva2EpR39OWZ9FworbX6vOAxsDvoGLzkCMHPQjiKLEG1gDXE9wDfeYJjefo_lLFkG88e01N5slarge time only the" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1262592 and 12 of them
}
