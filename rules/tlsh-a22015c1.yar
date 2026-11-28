rule Sightlines_tlsh_a22015c1_cobaltstrikebeacon
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a22015c1"
        date = "2026-11-25"
        campaign = "tlsh-a22015c1"
        family = "cobaltstrikebeacon"
        hash = "0c3afb30eca4de018a7a3aa42ab43acc4a3c998595ba1802da876feffb419bcc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a22015c1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "PaAgECMwYAcZ3ovh8b6S226yYSrm8GkyUakBzWCtmOKzF9azUnhsn+q5fZp+ib+TblhHd1nG01ncVNIpkRlQMiXQurRGzB8/w7eD" ascii
        $s1 = "tgO0tVEMeARGvue5/Ea5kSjXxCpBLBw88XJ78n92IwZrgMOJ2i1kpsI14CPaKBkmsdUzZFFf/y33RA/h9AbexYpochoLRJN6vlrj" ascii
        $s2 = "/jTLFxMogeifrc+kthr9l8vB0RmUej0bzInHO7TJd5Hvw1IGbUNVxkxDGZmLhP3tJFOd9D7LWFDVyEwH6WKnF2h+U65QozXvCMsA" ascii
        $s3 = "Z6apWNIYVfbNy4zH3neGwxelM98DYgsYuJHyhPUuyWxSXtOwec6osWS+BEr5EqtBATQzuMT+Eo/DP1mvOPtLbxlv5AZuFj6IdkBF" ascii
        $s4 = "rJd7fBdYhjzehIzuRZo4ZCWpN6oq5eOXjhklTmbHlE69M22SvoH8Fk7t+x8F8DKfvd+SpaeXLyAr45VGcsEiZMb+cx64vqPsV3BI" ascii
        $s5 = "J1y7ocf5nTbHYTDx5fO/JXVLxCkwBIHgDGzd2Eq5ol2HCxNmjZ4m0wTQH+r9gWvMFUeNppd7/iTIi8yXhhDlX3nZqAivBak2mtI4" ascii
        $s6 = "W0nMR66F8bn1cUop5CaR81aRWI+hHydFdF5scbVzbf7JojROppojvqLbYLictEHJxrEGNGXkDqZnlufSq/KmgujStHP/5Tw45Qih" ascii
        $s7 = "gDzesWpbVfAzZLymfkpUp6AK/Xvtx4rHR37DCG+FzLmPTA21uBucg596y5Wtwtft0GrSlZvrjbOQBoS7N8nMzAYXqY9Kujwm4yQq" ascii
        $s8 = "fbOGHKm4QnAj+VCrYG+SUCmrTc2XWMdGBPkGDgX/NhIB3LZv3CC4et65VcDgXuH1awJJPNoq8014a5/lBDKoR62TilntZxsP31Z2" ascii
        $s9 = "RZxAlD0PHRn9dUbho8ZN1QXM7tynvqIgEFcGcYzaxUXHUfa52TL6MM/0MdaIB7k4CzKTvYbTsqxqIJd+PCNY3reI/spL9w1GO3IQ" ascii
        $s10 = "zIrstkqpnhqBcCBg1Hf+ZB1FCteKNxlGGMiOAhb8yXc1MawXqlCuZWIkrFVYg/iY9Uj4Qsw/9ULupUmGxdodWSCsPEB7G41J5vVw" ascii
        $s11 = "4C7rA4VOVUjRcp9roH+DvNHBCgXOSDx19GI6nTLOEuFwEfaWUPvsWyKrx5lZnolHlh/G7hNPvdzQc+TZEIqupebDilY/SEQUMcfX" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
