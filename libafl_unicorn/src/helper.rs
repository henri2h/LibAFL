use unicorn_engine::{
    unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE},
    RegisterARM64,
};

#[must_use]
pub fn hash_me(mut x: u64) -> u64 {
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x) ^ x;
    x
}

pub fn memory_dump(emu: &mut unicorn_engine::Unicorn<()>, len: u64) {
    let pc = emu.reg_read(RegisterARM64::SP).unwrap();
    for i in 0..len {
        let pos = pc - len * 4 + i * 4;

        let data = emu.mem_read_as_vec(pos, 4).unwrap();

        println!(
            "{:X}:\t {:02X} {:02X} {:02X} {:02X}  {:08b} {:08b} {:08b} {:08b}",
            pos, data[0], data[1], data[2], data[3], data[0], data[1], data[2], data[3]
        );
    }
}
