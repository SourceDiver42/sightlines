rule Sightlines_host_e54a397e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-e54a397e"
        date = "2026-11-13"
        campaign = "host-e54a397e"
        family = ""
        hash = "07421fa99fa00e37581da99c96a71b68c20a4a999b90cfc32fb803cc752aff54"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-e54a397e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}" ascii
        $s1 = "Zizces_dihqig-bocoup_abpagem. Uttisi fofu-wov_i_jafe. Iygomiw hu. rotkaq_hecaib amuqo_kohadbe. Naxil" ascii
        $s2 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" ascii
        $s3 = "mu yuhko-kexgelte. qij_zujodga-dazki culuvu jewnequ. Wasacok_mo. Hetati_fe-vurre-zip tiq. Mepebu_rec" ascii
        $s4 = "Xar_wo ba-folaqe-jumir. Epcoy_yur. Luce-ticku nax-yii. Fasosi-sedhaq_packoc_zuc" ascii
        $s5 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\" ascii
        $s6 = "bolu_e-wi. daja-hawu. wevonbax_hir_gifqoka. Seecop cakpustu-yixiq_zu" ascii
        $s7 = "Iszug_lem_cimuq. hag_ejo uun-ci. di-fite_beuyge ap-vel. jakaxoh_vi. Odgofu zacafu-weste-dajcaxel-hun" ascii
        $s8 = "Onfisac-e. Yo_fik-dohebgu meqyux. Xaqe uw_jisaha-tilo" ascii
        $s9 = "Doe-fuyti. Enbac-va. xuuqaj iz_ro. Wapira-mowbo_qacano. Fe_zumuyo. xu_petolik. Pu_eaga-yid ta. Mafat" ascii
        $s10 = "Ko-ro. Ieyi_here zumuqca. Toc-za. ik-wajoto_bifassem_bilo_yaazij. Da-qeulgex-zigolsu-abingay_teni" ascii
        $s11 = "Az-vizav_uxes raco_pathuwi. e-biki-iji_qajfasoy-hi. Yi-guguv-niy nudho gacu. Co-omefu cidosal-hacod " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1918976 and 12 of them
}
