rule Sightlines_imphash_d735df00_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d735df00"
        date = "2026-11-17"
        campaign = "imphash-d735df00"
        family = ""
        hash = "29cf4a7b35e164e6856d0663b4da02efcd2fdc54bf62999620946a6f91071870"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d735df00.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "OURItPFy6AMvZBuhqLOvbgNHSwrUwFaQ3yzw5TicqrJkRnZMg4KjQbOUWX8JD7dhX3f1BUO9GnG_IVISREdeGtaVCMz0r_jYgXce" ascii
        $s1 = "5LP2VEdm7s9iuTg4u07Av4d-uz4_xWoGg.1l6IL0-qwFkaqlh2HDbrQitcG9klVY6mw_imBunfu6YOVMbYGOZnTSBpqUY4vNJ90y" ascii
        $s2 = "fvC7iA0WVgNWb.6qePwzk_4fKp3VmlDJmNHBucCpGLlsGO7-STQ2-.RhSqug56pK8xnXs5MhHoOHatKl7YcQWg5uuLM0Y.2AuF8v" ascii
        $s3 = "jjFfrctOETeEhnVtuaVcnLqWaik7BWAKpGuoom9Ao2MPs2zdWZcHtRhY-BckxYwKCexk71giX8.1yMSuPZW_-RV7v_J0DHT" ascii
        $s4 = "9Fy7xLUZEAB8y2XJ5WT_ZOfCuCL4VCyIBNgN0O3YL-IkDKbaqG4EJOPIlSoMepdqGvFkxWvYn59them than be why house wi" ascii
        $s5 = "xFLCHAxGkTxY1KRhnfrn-2Q0NzTVmqIfp.poeZkxCWld9dz-7mbmE4LM44Y3DO4TahSXygU0P.h5x_bsXS7MlonTuvbNZpRvhlua" ascii
        $s6 = "gwceSo44Nq79QLpPZkuMNP1Tj6pRatH8v.rhhfcAFQZKUH7ev1uA86xwQ6kVI-wDcEeS0nBfs.Uhpn3pyts5otsZvqEY6GiJE34X" ascii
        $s7 = "38amuMYCo2out204_fQ3xt0Trd1y8-dbjis_ZN6KIzqQCPdYgE5LBD3k0.N9nGwY7rJFICZfcb_A5cEh0g-uQJ-v-tl254LXrrsu" ascii
        $s8 = "8lSTe07U0xWCRgjqM8hcTCzIAnmIoVRfeuvx-lA5XaAED0r47kE0iQMi7jrdiOwFVMElZyLqxHbRBTcuwNfk4sL2U2v8peHEi5J6" ascii
        $s9 = "T2mozLkyJ8xZZ.4W2cnUngYw-cCEIYSG_yg2amDeqVbeAgLvHKfJH.aTlq7YLOsjU3qPeF0u-DGM46PD8xByapssRcyhO.CEECaS" ascii
        $s10 = "8ZdI_XiQQlQch9bLsev86ToCHIqK_3QCO1xHYR7kjUSE-zf1MNRRKxiKD-cEjpx0fZz1n3_irPn-z2F1gAVqRT7i4VmeGNgz7aQP" ascii
        $s11 = "b9cE3U5O5Vt6rx2Ofkc1Jqc1RiQ1TZ7Nr.SJyH60nPh-12zdQfvALAr98h_okehVIlmKyJdJ0.CbWqpZrBYgob15kXGcCxycd-mL" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1221632 and 12 of them
}
