#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = nbt_aad_release::read_zip(data, &nbt_aad_release::Limits::default()) {
        for (n, _) in &entries {
            assert!(!n.starts_with('/') && !n.contains("..") && !n.contains('\\'));
        }
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        let _ = nbt_aad_core::release::validate_archive_layout(&names);
    }
});
