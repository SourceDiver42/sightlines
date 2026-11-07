rule Sightlines_tlsh_bc61b93f_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bc61b93f"
        date = "2026-11-02"
        campaign = "tlsh-bc61b93f"
        family = "coinminer"
        hash = "0eadb9cc8098d0fb1ac1e80f13de901435a4c5e974ea0dc7306e037178e84ee0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bc61b93f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'&%$#\"! /.-,+*)(76543210?>=<;:98GFEDCBA@ONMLKJIHWVUTSRQP_^]\\[ZYXgfedcba`onmlkjihwvutsrqp" ascii
        $s1 = "CBA@GFEDKJIHONMLSRQPWVUT[ZYX_^]\\cba`gfedkjihonmlsrqpwvut{zyx" ascii
        $s2 = "const uint32_t mem_read_latency=((dst==src)&&((inst.y&ScratchpadL3Mask64)>=RANDOMX_SCRATCHPAD_L2))?S" ascii
        $s3 = "const uint32_t workers_mask=((1<<WORKERS_PER_HASH)-1)<<((get_local_id(0)/IDX_WIDTH)*IDX_WIDTH);" ascii
        $s4 = "__global uint2* p0=intermediate_programs+global_index*(INTERMEDIATE_PROGRAM_SIZE/sizeof(uint2));" ascii
        $s5 = "__global uint* p=programs+global_index*(COMPILED_PROGRAM_SIZE/sizeof(uint));" ascii
        $s6 = "__local uint32_t execution_plan_buf[RANDOMX_PROGRAM_SIZE*WORKERS_PER_HASH*(32/8)*sizeof(exec_t)/size" ascii
        $s7 = "const uint32_t fp_workers_mask=3<<(((sub>>1)<<1)+(get_local_id(0)/IDX_WIDTH)*IDX_WIDTH);" ascii
        $s8 = "} while ((first_available_slot<RANDOMX_PROGRAM_SIZE*WORKERS_PER_HASH)&&(execution_plan[first_availab" ascii
        $s9 = "Scratchpad+=get_group_id(0)*(MEMORY>>4)*WORKSIZE+MEM_CHUNK*get_local_id(0);" ascii
        $s10 = "((__global uint*)(R+19))[0]=(entropy[13]&DatasetExtraItems)*CacheLineSize;" ascii
        $s11 = "const int32_t num_workers=(inst>>NUM_INSTS_OFFSET)&(WORKERS_PER_HASH-1);" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12929024 and 12 of them
}
