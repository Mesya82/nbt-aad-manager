#![no_main]
libfuzzer_sys::fuzz_target!(|data: &str| {
    let mut o = nbt_aad_core::profile::Observation::default();
    let _ = o.add_readback_tsv(data);
});
