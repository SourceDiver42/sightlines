rule Sightlines_tlsh_84bdf483_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84bdf483"
        date = "2026-11-10"
        campaign = "tlsh-84bdf483"
        family = ""
        hash = "10fbfe4d9e0f9eed31caeb1a0fa2605ef1b1c36da477dceea75d5610541ad728"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84bdf483.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Rok pokrovitelja: rukopis predan, {0:0.0} od {1} mjeseci" wide
        $s4 = "Pisari rade pri dnevnom svjetlu ({0:0.0} h svjetla)." wide
        $s5 = "Tinta dostaje za oko {3:0} folija, pergament za {4:0} folija." wide
        $s6 = "The value for column 'DataColumn2' in table 'DataTable1' is DBNull." wide
        $s7 = "The value for column 'DataColumn3' in table 'DataTable1' is DBNull." wide
        $s8 = "The value for column 'DataColumn4' in table 'DataTable1' is DBNull." wide
        $s9 = "The value for column 'DataColumn5' in table 'DataTable1' is DBNull." wide
        $s10 = "The value for column 'DataColumn1' in table 'DataTable1' is DBNull." wide
        $s11 = "Dnevno svjetlo: {0:0.0} h, radnih sati: {1:0.0}" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1297408 and 12 of them
}
