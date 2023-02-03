use std::{fs::File, io::Read};

pub use libafl_targets::{edges_max_num, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE, MAX_EDGES_NUM};
use unicorn_engine::{
    unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Permission, SECOND_SCALE},
    RegisterARM64, Unicorn,
};

static DEBUG: bool = false;

static CODE_ADDRESS: u64 = 0x800;

use crate::{helper::memory_dump, hooks::block_hook};

pub struct Emulator {
    emu: unicorn_engine::Unicorn<'static, ()>,
    code_len: u64,
}

impl Emulator {
    pub fn new() -> Emulator {
        let emu = unicorn_engine::Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
            .expect("failed to initialize Unicorn instance");
        Emulator { emu, code_len: 0 }
    }

    pub fn setup(&mut self, input_addr: u64, input_size: usize) {
        self.code_len = load_code(&mut self.emu, CODE_ADDRESS);
        // TODO: For some reason, the compiled program start by substracting 0x10 to SP
        self.emu
            .mem_map(input_addr, input_size, Permission::ALL)
            .expect("failed to map data page");
    }

    pub fn run(&mut self) {
        prog(&mut self.emu, self.code_len);
    }

    pub fn write_mem(&mut self, addr: u64, buf: &[u8]) {
        //println!("{} -> {}", addr, addr + (buf.len() as u64));
        self.emu
            .mem_write(addr, &buf)
            .expect("failed to write instructions");
    }

    pub fn set_memory_hook(&mut self, addr: u64, length: u64) {
        self.emu
            .add_mem_hook(HookType::MEM_ALL, addr - length, addr, callback)
            .expect("Failed to register watcher");
    }

    pub fn set_code_hook(&mut self) {
        self.emu
            .add_block_hook(block_hook)
            .expect("Failed to register code hook");
    }

    pub fn write_reg<T>(&mut self, regid: T, value: u64)
    where
        T: Into<i32>,
    {
        self.emu.reg_write(regid, value).expect("Could not set registry");
    }
}

fn load_code(emu: &mut Unicorn<()>, address: u64) -> u64 {
    let mut f = File::open("libafl_unicorn_test/a.out").expect("Could not open file");
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer).expect("Could not read file");

    let arm_code = buffer;

    // Define memory regions
    emu.mem_map(
        address,
        ((arm_code.len() / 1024) + 1) * 1024,
        Permission::EXEC,
    )
    .expect("failed to map code page");

    // Write memory
    emu.mem_write(address, &arm_code)
        .expect("failed to write instructions");
    return arm_code.len() as u64;
}

fn debug_print(emu: &mut Unicorn<()>, err: uc_error) {
    println!();
    println!("Snap... something went wrong");
    println!("Error: {:?}", err);

    let pc = emu.pc_read().unwrap();
    println!();
    println!("Status when crash happened");

    println!("PC: {:X}", pc);
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
                println!(
                    "{:X}: {:03}:\t {:02X} {:02X} {:02X} {:02X}  {:08b} {:08b} {:08b} {:08b}",
                    pos,
                    dec,
                    data[0],
                    data[1],
                    data[2],
                    data[3],
                    data[0],
                    data[1],
                    data[2],
                    data[3]
                );
            }
            Err(_) => {}
        }
    }
}

fn callback(
    _unicorn: &mut unicorn_engine::Unicorn<()>,
    mem: MemType,
    address: u64,
    size: usize,
    value: i64,
) -> bool {
    if DEBUG {
        match mem {
            MemType::WRITE => println!(
                "Memory is being WRITTEN at adress: {:X} size: {} value: {}",
                address, size, value
            ),
            MemType::READ => println!(
                "Memory is being READ at adress: {:X} size: {}",
                address, size
            ),

            _ => println!(
                "Memory access type: {:?} adress: {:X} size: {} value: {}",
                mem, address, size, value
            ),
        }
    }

    return true;
}

pub fn emulate() {
    let mem_data = [0x50, 0x24, 0x0];
    // TODO
}

pub fn prog(emu: &mut unicorn_engine::Unicorn<'static, ()>, arm_code_len: u64) {
    if DEBUG {
        memory_dump(emu, 2);
    }

    let result = emu.emu_start(
        CODE_ADDRESS + 0x40, // start at main. Position of main: 0x40
        CODE_ADDRESS + arm_code_len,
        10 * SECOND_SCALE,
        0x1000,
    );

    match result {
        Ok(_) => {
            // never hapens

            assert_eq!(emu.reg_read(RegisterARM64::X0), Ok(100));
            assert_eq!(emu.reg_read(RegisterARM64::X1), Ok(1337));
        }
        Err(err) => {
            if emu.pc_read().unwrap() == 0 {
                if DEBUG {
                    println!("Reached start");
                }

                // check output
                let mut buf: [u8; 1] = [0];
                let pc = emu.reg_read(RegisterARM64::SP).unwrap();

                emu.mem_read(pc - 1, &mut buf)
                    .expect("Could not read memory");

                // check result
                if buf[0] != 0x4 {
                    // didn't found the correct value
                    return;
                }

                // success
                println!("Correct input found");
                println!("Output: {:#}", buf[0]);
                memory_dump(emu, 2);

                panic!("Success :)");
            } else {
                debug_print(emu, err);
            }
        }
    }
}
