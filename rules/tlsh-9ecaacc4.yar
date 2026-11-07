rule Sightlines_tlsh_9ecaacc4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9ecaacc4"
        date = "2026-11-05"
        campaign = "tlsh-9ecaacc4"
        family = ""
        hash = "02f9176dd9991231551873ed8917050e41cd5d967288d51fc54715446d6182c9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9ecaacc4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Provisions Split: {0}% Perishables (fresh meat/dairy/produce) vs {1}% Dry Goods (pasta/flour/tins)" wide
        $s1 = "Split: 40% Perishables (fresh meats/dairy/produce) vs 60% Dry Goods (grain/pasta/canned)" wide
        $s2 = "Delivery complete via {0}. Food +{1:0}kg, Fuel +{2:0}L, Waste evacuated {3:0}kg" wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "All elements conforming strictly to targetNamespace 'http://tempuri.org/MountainHutSupply.xsd'." wide
        $s5 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "XSD schema file 'MountainHutSupply.xsd' could not be found." wide
        $s7 = "<MountainHut.HutForm.IChannelSource.Produce>b__0" ascii
        $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s9 = "Evacuated {0:0}kg of rubbish and septic waste." wide
        $s10 = "XML schema validation successful against MountainHutSupply.xsd" wide
        $s11 = "Flawless alpine logistics: high supply completion, zero food/fuel exhaustion, and steady cistern lev" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1849344 and 12 of them
}
