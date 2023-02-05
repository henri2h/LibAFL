use unicorn_engine::{unicorn_const::Arch, RegisterARM, RegisterARM64, RegisterX86};

pub fn memory_dump(emu: &mut unicorn_engine::Unicorn<()>, len: u64) {
    let sp = get_stack_pointer(emu);
    for i in 0..len {
        let pos = sp + i * 4 - len * 4;

        let data = emu.mem_read_as_vec(pos, 4).unwrap();

        println!(
            "{:X}:\t {:02X} {:02X} {:02X} {:02X}  {:08b} {:08b} {:08b} {:08b}",
            pos, data[0], data[1], data[2], data[3], data[0], data[1], data[2], data[3]
        );
    }
}

pub fn get_stack_pointer(emu: &mut unicorn_engine::Unicorn<()>) -> u64 {
    let sp = match emu.get_arch() {
        Arch::ARM => emu.reg_read(RegisterARM::SP).unwrap(),
        Arch::ARM64 => emu.reg_read(RegisterARM64::SP).unwrap(),
        Arch::X86 => emu.reg_read(RegisterX86::ESP).unwrap(),
        _ => 0,
    };
    sp
}
