#![no_main]
libfuzzer_sys::fuzz_target!(|data: &str| {
    for e in nbt_aad_core::probe::parse_ls(data) {
        if let nbt_aad_core::probe::LsEntry::File { name, .. } = e {
            assert!(!name.chars().any(char::is_whitespace));
        }
    }
});
