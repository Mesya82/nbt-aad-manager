#![no_main]
libfuzzer_sys::fuzz_target!(|data: &str| {
    let entries: Vec<&str> = data.lines().collect();
    if nbt_aad_core::release::validate_archive_layout(&entries).is_ok() {
        assert!(entries.iter().all(|e| !e.contains("..") && !e.starts_with('/')));
    }
});
