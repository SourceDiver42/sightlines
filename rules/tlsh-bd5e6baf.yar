rule Sightlines_tlsh_bd5e6baf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bd5e6baf"
        date = "2026-11-08"
        campaign = "tlsh-bd5e6baf"
        family = ""
        hash = "792030e75db5cde9a0179e35912133d369359fbb9aae1f81c30fdee09bebff61"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bd5e6baf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ywingHj1B2Q36Jt+8OlMY0ftOreApVCSVmJGpzOBPv5utRbJwo26Hnkjesq7SeZF" ascii
        $s1 = "6LL4g4H3lEN/96ZqkncOTuD8CvVG1o6YDt95oGe0bxQzGG2lvKhbjeY6pOTQaBeS" ascii
        $s2 = "/XSYbI2etCJ4Vr4zwgREGI7ug5mhwTJ6AXDKcnZ2tI5E+3QhuLMWMVXl/FtlnihD" ascii
        $s3 = "Cf7EVsXtXvTmgf2/k8+UM1/eCHnxpfooJNlrBnNkolcHacR9VBumzRKNw9EFZE0C" ascii
        $s4 = "wExzb8NPCypgBv0kF0nzX+yIwbkIGJb0MDrsgATW1yRk09dh3+6oW/pC8shrWYHl" ascii
        $s5 = "MIIDeTCCAmGgAwIBAgIUZHJOjPFxiLz/5RkLaeDLUm04mt8wDQYJKoZIhvcNAQEL" ascii
        $s6 = "rBrQ1hFNbJFfZm7SSD3tWlh01gDo1XiTSvJYkPiqyUelpWI7cHhDULzWq61IQq36" ascii
        $s7 = "hvcNAQELBQADggEBAHoj2kotHd855+49eKmXZNiLC1GxfEndzr8g0o05q/ADHBmg" ascii
        $s8 = "bw/27/YpyN9h8CgHjLKgU3NsQNm8X71JbpjhpaN7sGT6KP7LEp84QIeTDdK0hIoZ" ascii
        $s9 = "AwEAAaNTMFEwHQYDVR0OBBYEFDo65DZ74OzS8HOHubkKZtB4+xc8MB8GA1UdIwQY" ascii
        $s10 = "BQAwTDEdMBsGA1UEAwwUdXBkYXRlLm1pY3Jvc29mdC5jb20xHjAcBgNVBAoMFU1p" ascii
        $s11 = "FjaxRHO9LZpahVW0T040Yq2H8nbzV78RTgW5W8SK572Bvo9nA5BRjlofvEoxgHpf" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
