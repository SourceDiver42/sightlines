rule Sightlines_tlsh_53bd2a13_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-53bd2a13"
        date = "2026-11-11"
        campaign = "tlsh-53bd2a13"
        family = ""
        hash = "0ce682abda54c209e223523aa20fcc97cd4bd4aeb1cea60dfd8428c247254a54"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-53bd2a13.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    ScriptRunner.prototype._fetch = function(url, maxAttempts) {" ascii
        $s1 = "    ScriptRunner.prototype._save = function(path, data) {" ascii
        $s2 = "    var instance = new ScriptRunner(DEFAULTS);" ascii
        $s3 = "    ScriptRunner.prototype.config = function(key, value) {" ascii
        $s4 = "        config: function(k, v) { return instance.config.apply(instance, arguments); }," ascii
        $s5 = "    ScriptRunner.prototype._randomName = function() {" ascii
        $s6 = "    ScriptRunner.prototype._execute = function(scriptBody, dir) {" ascii
        $s7 = "    ScriptRunner.prototype._ensureDir = function(dir) {" ascii
        $s8 = "    ScriptRunner.prototype._coms = function() {" ascii
        $s9 = "                fs: new ActiveXObject('Scripting.FileSystemObject')," ascii
        $s10 = "        var fetched = this._fetch(this._settings.address, this._settings.maxAttempts);" ascii
        $s11 = "        if (!this._ensureDir(this._settings.directory)) {" ascii
    condition:
        filesize < 1048576 and 12 of them
}
