use std::fs::File;
use std::io::Read;

use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, RegisterARM64};

fn callback(
    _unicorn: &mut unicorn_engine::Unicorn<()>,
    mem: MemType,
    number: u64,
    size: usize,
    other_number: i64,
) -> bool {
    println!(
        "Bad registration done number: {}, size: {}, other_number: {}",
        number, size, other_number
    );
    println!("MemType: {:?}", mem);
    return true;
}

fn emulate() {
    let address = 0x1000;
    let r_sp = 0x8000;
    let data_size = 0x1000;

    let mut f = File::open("libafl_unicorn_test/a.out").expect("Could not open file");
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer).expect("Could not read file");

    let arm_code = buffer;

    // [0x17, 0x00, 0x40, 0xe2]; // sub r0, #23
    println!("Program length: {}", arm_code.len());

    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");

    // Define memory regions
    emu.mem_map(
        address,
        ((arm_code.len() / 1024) + 1) * 1024,
        Permission::ALL,
    )
    .expect("failed to map code page");
    emu.mem_map(r_sp, data_size * 8, Permission::ALL)
        .expect("failed to map data page");

    // Write memory
    emu.mem_write(address, &arm_code)
        .expect("failed to write instructions");
    emu.mem_write(r_sp, &[0x2, 0x0])
        .expect("failed to write instructions");

    // Set registry
    // TODO: For some reason, the compiled program start by substracting 0x10 to SP
    emu.reg_write(RegisterARM64::SP, r_sp + 0x10)
        .expect("Could not set registery");

    // Add me mory hook
    emu.add_mem_hook(
        HookType::MEM_WRITE_UNMAPPED,
        r_sp,
        r_sp + (data_size) as u64,
        callback,
    )
    .expect("Failed to register watcher");

    println!("SP: {:X}", emu.reg_read(RegisterARM64::SP).unwrap());

    let result = emu.emu_start(
        address + 0x40, // start at main. Position of main: 0x40
        address + (arm_code.len()) as u64,
        10 * SECOND_SCALE,
        0x1000,
    );

    match result {
        Ok(_) => {
            println!("Ok");

            assert_eq!(emu.reg_read(RegisterARM64::X0), Ok(100));
            assert_eq!(emu.reg_read(RegisterARM64::X1), Ok(1337));
        }
        Err(err) => {
            if emu.pc_read().unwrap() == 0 {
                println!("Reached start");
                println!("Execution successfull ?");
            } else {
                println!();
                println!("Snap... something went wrong");
                println!("Error: {:?}", err);

                let pc = emu.pc_read().unwrap();
                println!();
                println!("Status when crash happened");

                println!("PC: {:X}", pc);
                println!("PC: {:X}", emu.reg_read(RegisterARM64::PC).unwrap());
                println!("SP: {:X}", emu.reg_read(RegisterARM64::SP).unwrap());
                println!("X0: {:X}", emu.reg_read(RegisterARM64::X0).unwrap());
                println!("X1: {:X}", emu.reg_read(RegisterARM64::X1).unwrap());
                println!("X2: {:X}", emu.reg_read(RegisterARM64::X2).unwrap());
                println!("X3: {:X}", emu.reg_read(RegisterARM64::X3).unwrap());

                println!();
                for i in 0..10 {
                    let pos = i * 4 + pc - 4 * 5; // Instruction are on 4 bytes
                    let dec = pos as i64 - pc as i64;

                    let read_result = emu.mem_read_as_vec(pos, 4);
                    match read_result {
                        Ok(data) => {
                            println!("{:X}: {:03}:\t {:02X} {:02X} {:02X} {:02X}  {:08b} {:08b} {:08b} {:08b}", pos, dec, data[0], data[1], data[2], data[3], data[0], data[1], data[2], data[3]);
                        }
                        Err(_) => {}
                    }
                }
            }
        }
    }
}

fn main() {
    emulate();
}
