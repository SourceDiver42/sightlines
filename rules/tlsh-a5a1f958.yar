rule Sightlines_tlsh_a5a1f958_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5a1f958"
        date = "2026-11-15"
        campaign = "tlsh-a5a1f958"
        family = ""
        hash = "0c434b7ce868cff226584e04657a3609eafd0ce28e242128ecb61f4c6b2bb059"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5a1f958.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Error:%08x in spFileNames->Write((LPCTSTR)stFullName, (stFullName.length() + 1)*sizeof(TCHAR), NULL)" wide
        $s1 = "Vals[MAX_KERNEL_SIZE];void main(void){    int i;    vec4 sum;    if (any(lessThan(gl_TexCoord[0].st," ascii
        $s2 = "Error:%08x in spFileNames->Write(_T(\"\"), sizeof(TCHAR), NULL)" wide
        $s3 = "Error:%08x in SHGetFolderPath( NULL, CSIDL_INTERNET_CACHE|CSIDL_FLAG_CREATE, NULL, 0, szPath)" wide
        $s4 = "Error:%08x in SHCreateStreamOnFile( pFileName, STGM_WRITE | STGM_CREATE, &spDst )" wide
        $s5 = "ns[MAX_FRACTIONS];uniform float scaleFactors[MAX_FRACTIONS-1];%s%svoid main(void){    float dist;   " ascii
        $s6 = "Error:%08x in ExtractNativeData(CF_FILECONTENTS, lIndex, &stgmedium)" wide
        $s7 = "Error:%08x in spFileNames->Stat(&st, STATFLAG_NONAME)" wide
        $s8 = "Error:%08x in CreateStreamOnHGlobal( stgmedium.hGlobal, FALSE, &spSrc )" wide
        $s9 = "Error:%08x in SHGetFolderPath( NULL, CSIDL_WINDOWS, NULL, 0, szPath)" wide
        $s10 = "RE_SIZE));const float HALF_TEXEL = (FULL_TEXEL / 2.0);uniform sampler1D colors;uniform float fractio" ascii
        $s11 = "((dist - fractions[i]) * scaleFactors[i], 0.0, 1.0);}tc = HALF_TEXEL + (FULL_TEXEL * relFraction);" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2986320 and 12 of them
}
