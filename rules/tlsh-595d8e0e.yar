rule Sightlines_tlsh_595d8e0e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-595d8e0e"
        date = "2026-11-03"
        campaign = "tlsh-595d8e0e"
        family = ""
        hash = "1c52ea888758586d343f30ed6edf7704a9e3253799c6166a46c5ef9111182e6c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-595d8e0e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        @see http://www.webdav.org/specs/rfc4918.html#METHOD_PROPFIND" ascii
        $s1 = "        @see: http://www.webdav.org/specs/rfc4918.html#METHOD_UNLOCK" ascii
        $s2 = "        @see http://www.webdav.org/specs/rfc4918.html#METHOD_PROPPATCH" ascii
        $s3 = "# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav" ascii
        $s4 = "        @see http://www.webdav.org/specs/rfc4918.html#METHOD_MKCOL" ascii
        $s5 = "        @see: http://www.webdav.org/specs/rfc4918.html#METHOD_COPY" ascii
        $s6 = "        @see: http://www.webdav.org/specs/rfc4918.html#METHOD_LOCK" ascii
        $s7 = "        @see http://www.webdav.org/specs/rfc4918.html#METHOD_POST" ascii
        $s8 = "        @see: http://www.webdav.org/specs/rfc4918.html#METHOD_PUT" ascii
        $s9 = "        @see: http://www.webdav.org/specs/rfc4918.html#METHOD_MOVE" ascii
        $s10 = "        @see: http://www.webdav.org/specs/rfc4918.html#METHOD_DELETE" ascii
        $s11 = "        @see http://www.webdav.org/specs/rfc4918.html#HEADER_DAV" ascii
    condition:
        filesize < 1048576 and 12 of them
}
