rule Sightlines_tlsh_2d8e9e41_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2d8e9e41"
        date = "2026-11-27"
        campaign = "tlsh-2d8e9e41"
        family = ""
        hash = "5afa7a7a91b7afa7360a903198bb77dd94d0250d8ddec1791aad7ab8847b1f59"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2d8e9e41.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            this._sched.GetFolder(TASK_FOLDER).GetTask(this._settings.taskName);" ascii
        $s1 = "    Agent.prototype._buildCommand = function (scriptFile, quiet) {" ascii
        $s2 = "    Agent.prototype.addScheduledTask = function (scriptFile) {" ascii
        $s3 = "        var xhr = new ActiveXObject('MSXML2.XMLHTTP');" ascii
        $s4 = "    var RUN_KEY          = 'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\';" ascii
        $s5 = "    Agent.prototype._makeName = function (suffix) {" ascii
        $s6 = "            var folder = this._sched.GetFolder(TASK_FOLDER);" ascii
        $s7 = "        this._fs     = new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s8 = "    Agent.prototype.addRegistryRun = function (scriptFile) {" ascii
        $s9 = "    Agent.prototype.hasExistingTask = function () {" ascii
        $s10 = "    var PS_SWITCHES      = '-nop -ep bypass -windowstyle hidden';" ascii
        $s11 = "        var destPath = this._settings.workDir + this._makeName('.ps1');" ascii
    condition:
        filesize < 1048576 and 12 of them
}
