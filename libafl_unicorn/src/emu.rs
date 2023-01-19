use std::{cell::UnsafeCell, cmp::max, error::Error, fs::File, io::Read, path::PathBuf};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes, UsesInput},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasMetadata, StdState},
};
pub use libafl_targets::{edges_max_num, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE, MAX_EDGES_NUM};
use unicorn_engine::{
    unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Permission, SECOND_SCALE},
    RegisterARM64, Unicorn,
};

static debug: bool = false;
static showInputs: bool = true;

use crate::{
    helper::{hash_me, memory_dump},
    hooks::block_hook,
};

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
                dbg!(
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
    if debug {
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
    prog(&mem_data);
}

// The closure that we want to fuzz
pub fn harness(input: &BytesInput) -> ExitKind {
    // convert input bytes
    let target = input.target_bytes();
    let buf = target.as_slice();
    if showInputs {
        dbg!(buf);
    }

    println!("Run prog");
    let result = prog(buf);

    if debug {
        unsafe {
            for val in 0..EDGES_MAP.len() {
                if EDGES_MAP[val] != 0 {
                    dbg!(val, EDGES_MAP[val]);
                }
            }
        };
    }

    return result;
}

static mut EMU: Option<unicorn_engine::Unicorn<'static, ()>> = None;

fn prog(buf: &[u8]) -> ExitKind {
    let address: u64 = 0x1000;
    let r_sp: u64 = 0x8000;
    let data_size: usize = 0x100;

    // [0x17, 0x00, 0x40, 0xe2]; // sub r0, #23

    let mapped_addr = r_sp - (data_size as u64) * 8;
    let mapped_len = data_size * 8;

    let mut arm_code_len = 0;

    let mut emu = unsafe {
        EMU.get_or_insert_with(|| {
            let mut emu = unicorn_engine::Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
                .expect("failed to initialize Unicorn instance");

            arm_code_len = load_code(&mut emu, address);

            // TODO: For some reason, the compiled program start by substracting 0x10 to SP
            emu.mem_map(mapped_addr, mapped_len, Permission::ALL)
                .expect("failed to map data page");

            // Add me mory hook
            emu.add_mem_hook(HookType::MEM_ALL, r_sp - (data_size) as u64, r_sp, callback)
                .expect("Failed to register watcher");

            emu.add_block_hook(block_hook)
                .expect("Failed to register code hook");

            emu
        })
    };

    // Set registry
    // TODO: For some reason, the compiled program start by substracting 0x10 to SP
    emu.reg_write(RegisterARM64::SP, r_sp)
        .expect("Could not set registery");

    // TODO specific values
    let mem_data = buf;
    emu.mem_write(r_sp - (mem_data.len() as u64), &mem_data)
        .expect("failed to write instructions");

    if debug {
        memory_dump(&mut emu, 2);
    }

    if debug {
        println!("SP: {:X}", emu.reg_read(RegisterARM64::SP).unwrap());
    }

    let result = emu.emu_start(
        address + 0x40, // start at main. Position of main: 0x40
        address + arm_code_len,
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
                if debug {
                    println!("Reached start");
                }

                // check output
                let mut buf: [u8; 1] = [0];
                let pc = emu.reg_read(RegisterARM64::SP).unwrap();

                emu.mem_read(pc - 1, &mut buf)
                    .expect("Could not read memory");

                // check result
                if buf[0] != 0x4 {
                    // error here
                    return ExitKind::Ok;
                }

                // success
                println!("Correct input found");
                dbg!(buf);
                memory_dump(&mut emu, 2);

                panic!("Success :)");
                return ExitKind::Ok;
            } else {
                debug_print(&mut emu, err);
            }
        }
    }

    ExitKind::Ok
}
