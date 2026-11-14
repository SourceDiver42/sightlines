rule Sightlines_tlsh_6700b38f_strrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6700b38f"
        date = "2026-11-07"
        campaign = "tlsh-6700b38f"
        family = "strrat"
        hash = "19f115d1668173786d59b1f39f2b9918a720d76dc3de2fc1edb5458496affcae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6700b38f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "eval('String.prototype.testimOnly = function(){var _obj = WScript[\"CreateObject\"](\"\".getString(\"046\"" ascii
        $s1 = "var asc = WSH[\"CreateObject\"](\"UTF8Encoding\"[\"getString\"](\"34d4\"));" ascii
        $s2 = "))[\"createElement\"](\"xyz\");_obj.dataType = \"hex\".getString(84);_obj.text = this.toString();return _o" ascii
        $s3 = "var byted=de[\"TransformFinalBlock\"](data,0,dLen);" ascii
        $s4 = "var yrotsiH=WSH[\"CreateObject\"](\"RijndaelManaged\"[\"getString\"](\"34e4c4\"));" ascii
        $s5 = "result += data[parseInt(key.toString().substr(i, 1), 16)];" ascii
        $s6 = "var arr = WScript.CreateObject(\"\".getString(342491));" ascii
        $s7 = "var adoStr = WScript.CreateObject(\"\".getString(541));" ascii
        $s8 = "var iv = pipeLine(raw.nodeTypedValue, 32, 16);" ascii
        $s9 = "for(var i=0; i<key.toString().length; i++){" ascii
        $s10 = "var key = pipeLine(raw.nodeTypedValue, 0, 32);" ascii
        $s11 = "var data = pipeLine(raw.nodeTypedValue, 48, dLen);" ascii
    condition:
        filesize < 1698456 and 12 of them
}
