#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(meta) = nbt_aad_release::parse_release_json(data) {
        let _ = nbt_aad_core::release::select_assets(nbt_aad_core::release::KNOWN, &meta.tag, &meta);
    }
});
