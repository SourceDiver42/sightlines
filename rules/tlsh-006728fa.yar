rule Sightlines_tlsh_006728fa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-006728fa"
        date = "2026-11-18"
        campaign = "tlsh-006728fa"
        family = ""
        hash = "021a2dce703b90a6ce8295c1f96ec7a652d1d7e8a32b4e1cb1373382cea92080"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-006728fa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "jINSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '7d73d21f1bd82c9e5268b6dcf9f" ascii
        $s1 = "SELECT MAX(?-COUNT(*), 0) FROM workspec WHERE schedule_requested_at<>-1 AND LENGTH(content_uri_trigg" ascii
        $s2 = "}UPDATE workspec SET next_schedule_time_override=9223372036854775807 WHERE (id=? AND next_schedule_t" ascii
        $s3 = "^Select COUNT(*) FROM workspec WHERE LENGTH(content_uri_triggers)<>0 AND state NOT IN (2, 3, 5)" ascii
        $s4 = "SELECT * FROM workspec WHERE state=0 AND schedule_requested_at=-1 AND LENGTH(content_uri_triggers)<>" ascii
        $s5 = "lALTER TABLE `WorkSpec` ADD COLUMN `next_schedule_time_override` INTEGER NOT NULL DEFAULT 9223372036" ascii
        $s6 = "^INSERT OR REPLACE INTO `SystemIdInfo` (`work_spec_id`,`generation`,`system_id`) VALUES (?,?,?)" ascii
        $s7 = "@SELECT * FROM SystemIdInfo WHERE work_spec_id=? AND generation=?" ascii
        $s8 = "854775807, `next_schedule_time_override_generation` INTEGER NOT NULL DEFAULT 0, `stop_reason` INTEGE" ascii
        $s9 = "LL DEFAULT 0, `system_id` INTEGER NOT NULL, PRIMARY KEY(`work_spec_id`, `generation`), FOREIGN KEY(`" ascii
        $s10 = "vSELECT COUNT(*)=0 FROM dependency WHERE work_spec_id=? AND prerequisite_id IN (SELECT id FROM works" ascii
        $s11 = "max_content_delay` INTEGER NOT NULL, `content_uri_triggers` BLOB NOT NULL, PRIMARY KEY(`id`))" ascii
    condition:
        filesize < 1048576 and 12 of them
}
