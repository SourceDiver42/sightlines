rule Sightlines_imphash_6f114d90_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6f114d90"
        date = "2026-11-27"
        campaign = "imphash-6f114d90"
        family = ""
        hash = "3115cf07e28b5124d431c87bbb97221e1328f2ac1d752f0573925db2006e91ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6f114d90.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$CArqSessionT@VCUdpSocket@@V1@@@" ascii
        $s1 = "d40dd757c591be20399357567ef46b86b4c1d0009832e73559becfaa82a3ad7036a44d13e3e2185bb23fdcfe838283becc1e" ascii
        $s2 = "1f4afcb7c96ba486cb479fea6b2e47c44552dde8f82b27f01401edf96e7b54c1db61fc49c314d6d41b36433859c4f8052b35" ascii
        $s3 = "bbea3ce3755917b3f244b6cd410885654b9172d31abf95c85d6b96436a4b7dd688b42b25f861844bc4adf5ec47a925cddf73" ascii
        $s4 = "c99ceb29d50261a7a73584b5bbbb91d0c5be269444eac62618087ae896f70294aed2712b26a72f1cdb4888425b297212f7de" ascii
        $s5 = "ee2921d8eb4fba7a8147d25b5fde941e3a1130a93d159e54e0c2eab04aaafac31bfdd4129ef0fa40756181fd3d0eca2c0cc1" ascii
        $s6 = "input ack: sn=%lu rtt=%ld rto=%ld" ascii
        $s7 = ".?AVGdiplusBase@Gdiplus@@" ascii
        $s8 = "input psh: sn=%lu ts=%lu" ascii
        $s9 = ".?AVBitmap@Gdiplus@@" ascii
        $s10 = ".?AVImage@Gdiplus@@" ascii
        $s11 = ".?AVCLoginManager@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
