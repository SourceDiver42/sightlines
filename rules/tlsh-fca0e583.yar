rule Sightlines_tlsh_fca0e583_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fca0e583"
        date = "2026-10-15"
        campaign = "tlsh-fca0e583"
        family = ""
        hash = "029b03807c184b47ff2dd6b12b6863d478c955e77aa28dfa5c1e41170e1582ec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fca0e583.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        'WQFcKe4VwmodWRiSWRrGyGBcRSkCvw/cS8kPFSkiW5TIfLq0WOPKWQ9tW7SlgYRcOKpdHSkqwG'," ascii
        $s1 = "    var _0x3941ab = _0x153578, _0x1ff19 = new ActiveXObject('Scripting.FileSystemObject'), _0x327902" ascii
        $s2 = "_0x45094b] = _0x47080f, _0x37cb16 += String['fromCharCode'](_0x52f160['charCodeAt'](_0x53e6f0) ^ _0x" ascii
        $s3 = "        'osXgWOHYhCofW5GTESk0W5HICCk4fmkyWOvrWQxdJfldLmk/W7BdJqO3bYCBmh7cLmoWWOuOW5W'," ascii
        $s4 = "0x2e1e63, _0x15713d++ % 0x4) ? _0x5f0495 += String['fromCharCode'](0xff & _0x8bd6b5 >> (-0x2 * _0x15" ascii
        $s5 = " = new ActiveXObject(_0x241a86(0xb)), _0x5567be = new ActiveXObject(_0x241a86(0x6));" ascii
        $s6 = "charAt'](_0x16c375++); ~_0x2e1e63 && (_0x8bd6b5 = _0x15713d % 0x4 ? _0x8bd6b5 * 0x40 + _0x2e1e63 : _" ascii
        $s7 = " _0x47e244 = _0x2a1b['IkeedN'](_0x47e244, _0x2a1b2c), _0x2a1b['gRDGQH'][_0x237bd3] = _0x47e244) : _0" ascii
        $s8 = "    var _0x29e03d = _0x2a1b['gRDGQH'][_0x237bd3];" ascii
        $s9 = "_0x1c257c['length'])) % 0x100, _0x47080f = _0x4866af[_0x21b1d0], _0x4866af[_0x21b1d0] = _0x4866af[_0" ascii
        $s10 = "    function _0x2030db(_0x8971ea, _0x3ce2b4) {" ascii
        $s11 = "function _0x1564(_0x2c72ce, _0x7b9d5) {" ascii
    condition:
        filesize < 1048576 and 12 of them
}
