rule Sightlines_tlsh_aca0492c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aca0492c"
        date = "2026-11-10"
        campaign = "tlsh-aca0492c"
        family = ""
        hash = "43a366e5ff7e60505a06499e4eac43d249e111f03e8d50cd48234ace713b012d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aca0492c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "igurations.{vbCrLf}{vbCrLf}Framework: .NET Framework 4.6 | Language: VB.NET{vbCrLf}" wide
        $s1 = "Full tempo synchronization applied for patch '{0}' at {1:yyyy-MM-dd HH:mm:ss} UTC" wide
        $s2 = "JSON Patch Files (*.json)|*.json|XML Patch Files (*.xml)|*.xml|Legacy Patch Files (*.ptch)|*.ptch|Al" wide
        $s3 = "MIDI clock transmission STOPPED after {0:N0} pulses" wide
        $s4 = "egrating synthesizers, drum machines, and{vbCrLf}external sequencers with consistent BPM-locked conf" wide
        $s5 = "Primary beats-per-minute target for fixed tempo synchronization. Range: 20-300 BPM." wide
        $s6 = "MIDI clock transmission STARTED at {0} BPM, division factor {1}" wide
        $s7 = "Search executed for keyword: '{0}', found {1} match(es)." wide
        $s8 = "Drum machine kit locked to 174 BPM for drum-and-bass production. Uses standard MIDI clock without ve" wide
        $s9 = "Fixed Tempo Synchronization Console for hardware patch management.{vbCrLf}Designed for musicians int" wide
        $s10 = "Optimized for Juno-106 hardware integration. Fixed at 96 BPM for consistent ambient layering." wide
        $s11 = "Secondary BPM value {0} is outside valid range [20-300]." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3322880 and 12 of them
}
