use std::{fs::File, io::Read};

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
pub use libafl_targets::{edges_max_num, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE, MAX_EDGES_NUM};
use unicorn_engine::{
    unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Permission, SECOND_SCALE},
    RegisterARM, RegisterARM64, RegisterX86, Unicorn,
};

static DEBUG: bool = false;

static CODE_ADDRESS: u64 = 0x9000;
static HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

use crate::{
    helper::{get_stack_pointer, memory_dump},
    hooks::block_hook,
};

pub struct Emulator {
    emu: unicorn_engine::Unicorn<'static, ()>,
    code_len: u64,
}

impl Emulator {
    pub fn new(arch: Arch) -> Emulator {
        let emu = unicorn_engine::Unicorn::new(
            arch,
            match arch {
                Arch::ARM => Mode::ARM,
                Arch::ARM64 => Mode::ARM,
                Arch::X86 => Mode::MODE_64,
                _ => Mode::MODE_64,
            },
        )
        .expect("failed to initialize Unicorn instance");
        Emulator { emu, code_len: 0 }
    }

    pub fn setup(&mut self, input_addr: u64, input_size: usize, code_path: &str) {
        self.code_len = load_code(&mut self.emu, CODE_ADDRESS, code_path);
        // TODO: For some reason, the compiled program start by substracting 0x10 to SP
        self.emu
            .mem_map(input_addr, input_size, Permission::WRITE | Permission::READ)
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

    pub fn positioned_write(&mut self, addr: u64, end_addr: u64, buf: &[u8]) {
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
        self.emu
            .reg_write(regid, value)
            .expect("Could not set registry");
    }

    pub fn reg_read<T>(&self, regid: T) -> Result<u64, uc_error>
    where
        T: Into<i32>,
    {
        self.emu.reg_read(regid)
    }

    pub fn get_arch(&self) -> Arch {
        return self.emu.get_arch();
    }
}

fn load_code(emu: &mut Unicorn<()>, address: u64, path: &str) -> u64 {
    let mut f = File::open(path).expect("Could not open file");
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer).expect("Could not read file");

    let arm_code = buffer;

    // Define memory regions
    emu.mem_map(
        address,
        match emu.get_arch() {
            Arch::ARM => ((arm_code.len() / 1024) + 1) * 1024,
            Arch::ARM64 => ((arm_code.len() / 1024) + 1) * 1024,
            Arch::X86 => ((arm_code.len() / 4096) + 1) * 4096,
            _ => 0,
        },
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
    let arch = emu.get_arch();

    match arch {
        Arch::ARM => {
            println!("SP: {:X}", emu.reg_read(RegisterARM::SP).unwrap());
        }
        Arch::ARM64 => {
            println!("SP: {:X}", emu.reg_read(RegisterARM64::SP).unwrap());
            println!("X0: {:X}", emu.reg_read(RegisterARM64::X0).unwrap());
            println!("X1: {:X}", emu.reg_read(RegisterARM64::X1).unwrap());
            println!("X2: {:X}", emu.reg_read(RegisterARM64::X2).unwrap());
            println!("X3: {:X}", emu.reg_read(RegisterARM64::X3).unwrap());
        }
        Arch::X86 => {
            println!("ESP: {:X}", emu.reg_read(RegisterX86::ESP).unwrap());
            println!("RAX: {:X}", emu.reg_read(RegisterX86::RAX).unwrap());
            println!("RCX: {:X}", emu.reg_read(RegisterX86::RCX).unwrap());
            println!("RPB: {:X}", emu.reg_read(RegisterX86::RBP).unwrap());
            println!("RSP: {:X}", emu.reg_read(RegisterX86::RSP).unwrap());
            println!("EAX: {:X}", emu.reg_read(RegisterX86::EAX).unwrap());
            println!("ECX: {:X}", emu.reg_read(RegisterX86::ECX).unwrap());
            println!("EDX: {:X}", emu.reg_read(RegisterX86::EDX).unwrap());
        }
        _ => {}
    }

    if emu.get_arch() == Arch::X86 {
        // Provide dissasembly at instant of crash for X86 assembly
        let regions = emu.mem_regions().expect("Could not get memory regions");
        for i in 0..regions.len() {
            if regions[i].perms == Permission::EXEC {
                if pc >= regions[i].begin && pc <= regions[i].end {
                    let mut begin = pc - 32;
                    let mut end = pc + 32;
                    if begin < regions[i].begin {
                        begin = regions[i].begin;
                    }
                    if end > regions[i].end {
                        end = regions[i].end;
                    }

                    let bytes = emu
                        .mem_read_as_vec(begin, (end - begin) as usize)
                        .expect("Could not get program code");

                    let mut decoder = Decoder::with_ip(64, &bytes, begin, DecoderOptions::NONE);

                    let mut formatter = NasmFormatter::new();
                    formatter.options_mut().set_digit_separator("`");
                    formatter.options_mut().set_first_operand_char_index(10);

                    let mut instruction = Instruction::default();
                    let mut output = String::new();

                    while decoder.can_decode() {
                        decoder.decode_out(&mut instruction);

                        // Format the instruction ("disassemble" it)
                        output.clear();
                        formatter.format(&instruction, &mut output);

                        let diff = instruction.ip() as i64 - pc as i64;
                        print!("{:02}\t{:016X} ", diff, instruction.ip());
                        let start_index = (instruction.ip() - begin) as usize;
                        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
                        for b in instr_bytes.iter() {
                            print!("{:02X}", b);
                        }
                        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
                            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                                print!("  ");
                            }
                        }
                        println!(" {}", output);
                    }
                }
            }
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

pub fn prog(emu: &mut unicorn_engine::Unicorn<'static, ()>, arm_code_len: u64) {
    let result = emu.emu_start(
        match emu.get_arch() {
            Arch::ARM64 => CODE_ADDRESS + 0x40, // Position of main: 0x40 TODO: see if possible to get the main position from header file. Seems weird doing so
            _ => CODE_ADDRESS,
        },
        CODE_ADDRESS + arm_code_len,
        10 * SECOND_SCALE,
        0x1000,
    );

    match result {
        Ok(_) => {
            // never hapens
            panic!("huh");
        }
        Err(err) => {
            let mut instruction = [0];

            let pc = emu.pc_read().unwrap();
            let sp = get_stack_pointer(emu);

            if emu.get_arch() == Arch::X86 {
                emu.mem_read(pc, &mut instruction)
                    .expect("could not read at pointer address");
            }

            if pc == 0 || instruction[0] == 0xC3 {
                // Did we reached the beginning of the stack or is it a return ?
                if DEBUG {
                    println!("Reached start");
                }

                // check output
                let mut buf: [u8; 1] = [0];

                emu.mem_read(sp - 1, &mut buf)
                    .expect("Could not read memory");

                // check result
                if buf[0] != 0x4 {
                    // didn't found the correct value
                    if DEBUG {
                        println!("Incorrect output found!");
                        println!("Output: {:#}", buf[0]);

                        memory_dump(emu, 2);
                    }
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
