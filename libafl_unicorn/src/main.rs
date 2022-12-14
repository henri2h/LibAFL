use std::fs::File;
use std::io::Read;

use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};
use unicorn_engine::RegisterARM;

fn callback(
    unicorn: &mut unicorn_engine::Unicorn<()>,
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

    let mut f = File::open("test/a.out").expect("Could not open file");
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer).expect("Could not read file");

    let arm_code32 = buffer; /*[
                                 0x9a, 0x42, 0x15, 0xbf, 0x00, 0x9a, 0x01, 0x9a, 0x78, 0x23, 0x15, 0x23,
                             ];*/
    //buffer;
    // cmp r2, r3; itete
    // ne; ldrne r2,
    // [sp]; ldreq r2,
    // [sp,#4]; movne
    // r3, #0x78; moveq
    // r3, #0x15

    // [0x17, 0x00, 0x40, 0xe2]; // sub r0, #23
    println!("Program length: {}", arm_code32.len());

    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");

    // Define memory regions
    emu.mem_map(
        address,
        ((arm_code32.len() / 1024) + 1) * 1024,
        Permission::ALL,
    )
    .expect("failed to map code page");
    emu.mem_map(r_sp, data_size * 8, Permission::ALL)
        .expect("failed to map data page");

    // Write memory
    emu.mem_write(address, &arm_code32)
        .expect("failed to write instructions");
    emu.mem_write(r_sp, &[0x2, 0x0])
        .expect("failed to write instructions");

    // Set registry
    emu.reg_write(RegisterARM::SP, r_sp)
        .expect("Could not set registery");

    // Add me mory hook
    emu.add_mem_hook(
        HookType::MEM_WRITE_UNMAPPED,
        r_sp,
        r_sp + (data_size) as u64,
        callback,
    )
    .expect("Failed to register watcher");

    let result = emu.emu_start(
        address,
        address + (arm_code32.len()) as u64,
        10 * SECOND_SCALE,
        0x1000,
    );

    match result {
        Ok(_) => {
            println!("Ok");

            assert_eq!(emu.reg_read(RegisterARM::R0), Ok(100));
            assert_eq!(emu.reg_read(RegisterARM::R5), Ok(1337));
        }
        Err(err) => {
            println!();
            println!("Snap... something went wrong");
            println!("Error: {:?}", err);

            let pc = emu.pc_read().unwrap();
            println!();
            println!("Status when crash happened");

            println!("PC: {:X}", pc);
            println!("SP: {:X}", emu.reg_read(RegisterARM::SP).unwrap());
            println!("R0: {:X}", emu.reg_read(RegisterARM::R0).unwrap());
            println!("R1: {:X}", emu.reg_read(RegisterARM::R1).unwrap());
            println!("R2: {:X}", emu.reg_read(RegisterARM::R2).unwrap());
            println!("R3: {:X}", emu.reg_read(RegisterARM::R3).unwrap());

            println!();
            for i in 0..10 {
                let pos = pc + i * 2 - 10;

                let read_result = emu.mem_read_as_vec(pos, 2);
                match read_result {
                    Ok(data) => {
                        println!("{:X}: {}:\t 0x{:X}\t0x{:X}", pos, i as i64 - 5, data[0], data[1]);
                    }
                    Err(err) => {
                        println!("{:X} Err: {:?}", pos, err);
                    }
                }
            }
        }
    }
}

fn main() {
    emulate();
}
