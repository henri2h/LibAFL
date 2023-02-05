pub mod emu;
pub mod helper;
pub mod hooks;

use std::{char::MAX, env, path::PathBuf, time::Duration};

use emu::Emulator;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::StdState,
};
pub use libafl_targets::{EDGES_MAP_PTR, EDGES_MAP_SIZE};
use unicorn_engine::{unicorn_const::Arch, RegisterARM64, RegisterX86};

pub const MAX_INPUT_SIZE: usize = 0x8000; //1048576; // 1MB

// emulating
fn fuzzer(should_emulate: bool) {
    let input_addr_end: u64 = 0x8000;
    let input_addr_start: u64 = input_addr_end - MAX_INPUT_SIZE as u64;
    let emu = &mut Emulator::new(unicorn_engine::unicorn_const::Arch::X86);
    emu.setup(
        input_addr_start,
        MAX_INPUT_SIZE,
        "libafl_unicorn_test/foo_x86",
    );
    emu.set_code_hook();

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
        }

        emu.write_mem(input_addr_end - buf.len() as u64, buf);

        match emu.get_arch() {
            Arch::ARM | Arch::ARM64 => {
                emu.write_reg(RegisterX86::SP, input_addr_end);
            }

            Arch::X86 => {
                // clean emulator state
                for i in 1..259 {
                    emu.write_reg(i, 0);
                }

                emu.write_reg(RegisterX86::ESP, input_addr_end);
            }
            _ => {}
        }

        emu.run();

        return ExitKind::Ok;
    };

    if should_emulate {
        let mem_data: Vec<u8> = vec![0x50, 0x24, 0x0];
        harness(&BytesInput::from(mem_data));
        return;
    }

    let timeout = Duration::from_secs(1);

    let monitor = MultiMonitor::new(|s| println!("{s}"));
    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::<_, EDGES_MAP_SIZE>::from_mut_ptr(
            "edges",
            EDGES_MAP_PTR,
        ))
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new_tracking(&edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the executor");

    let mut executor = TimeoutExecutor::new(executor, timeout);

    // Generator of printable bytearrays of max size 32
    let mut generator = RandBytesGenerator::new(4);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let mut emu = false;
    if args.len() > 1 {
        if args[1] == "emu" {
            emu = true;
        }
    }
    fuzzer(emu);
}
