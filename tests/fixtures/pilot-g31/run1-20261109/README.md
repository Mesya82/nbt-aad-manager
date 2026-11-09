# Pilot head unit — probe run 1 (2026-11-09)

Source: `nbt-aad-manager probe` v0.0.1 (Rust, Windows x86_64) against the
pilot vehicle's NBT EVO (BMW G31 530i, 2018), direct ENET, SSH already
enabled, Android Auto force-stopped after a fresh boot.

Outcome: **stopped before login** (exit 2). The unauthenticated algorithm
capture succeeded; the host-key exchange failed with "Key exchange init
failed" because russh's default minimum DH group-exchange prime (3072 bits)
rejected the server's 2048-bit group. No command was executed on the head
unit; nothing was written.

`ssh-kexinit.txt` is unmodified (it contains no personal data). It is the
pinned fixture for `kexinit::tests::pilot_head_unit_fixture_*` and the
`pilot_head_unit_algorithm_set_with_2048_bit_gex_group` transport test.
