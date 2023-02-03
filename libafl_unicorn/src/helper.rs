use unicorn_engine::RegisterARM64;

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
