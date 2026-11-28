rule Sightlines_tlsh_973dccff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-973dccff"
        date = "2026-11-19"
        campaign = "tlsh-973dccff"
        family = ""
        hash = "1fd1762a669a1e514e7c5bf2e40059ae9c57c10f42ea799aaaf8a70a3d5c1116"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-973dccff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\",2,15),e.fillStyle=\"rgba(102, 204, 0, 0.7)\",e.font=\"18pt Arial\",e.fillText(\"Cwm fjordbank glyphs ve" ascii
        $s1 = "92653589793\"),n=function(n){return eval(t+\" ** -100\")==+(\"1.9275814160560\"+n+\"e-50\")},r=n(204),e=n(1" ascii
        $s2 = "en(function(n){if(n&&n.length){for(var e=0;e<n.length;e++){var i=n[e];i&&i.kind&&a.hasOwnProperty(i." ascii
        $s3 = "kind)&&a[i.kind]++}r={s:a.audiooutput,m:a.audioinput,w:a.videoinput},t(r)}else t(r={s:0,m:0,w:0})})." ascii
        $s4 = "=r?String.fromCharCode(n>>16&255):64===e?String.fromCharCode(n>>16&255,n>>8&255):String.fromCharCode" ascii
        $s5 = "Root.querySelector('button[data-action-btn=\"true\"]');if(n&&\"Take over\"===n.innerText)return n}catch(" ascii
        $s6 = "oContext(1,1,44100).createAnalyser(),n=new Float32Array(t.frequencyBinCount);return t.getFloatFreque" ascii
        $s7 = "r,r=!1;t.exports={collect:function(t){try{if(r)return t(r);var e,i=\"bound reportBlock\",a={audiooutpu" ascii
        $s8 = "(function(){var t={395:function(t,n,r){var e=r(19),i=r(539);t.exports=function(t,n){try{var r=e(!0,!" ascii
        $s9 = "on(){t({w:this.naturalWidth,h:this.naturalHeight})},n.src=d([102,107,117,114,112,104,61,50,50,101,11" ascii
        $s10 = "odeValue&&r.nodeName&&r.nodeValue.length<=50&&r.nodeName.length<=50){var i=n.indexOf(r.nodeName),a=t" ascii
        $s11 = "=function(){try{var t=document.elementFromPoint(0,0);return t||(t=document.elementFromPoint(1,1)),t}" ascii
    condition:
        filesize < 1048576 and 12 of them
}
