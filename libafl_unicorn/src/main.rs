pub mod emu;
pub mod helper;
pub mod hooks;

#[cfg(windows)]
use std::ptr::write_volatile;
use std::{
    cell::UnsafeCell, cmp::max, fs::File, io::Read, path::PathBuf, ptr::addr_of_mut, time::Duration,
};

use hashbrown::{hash_map::Entry, HashMap};
#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{RandBytesGenerator, RandPrintablesGenerator},
    inputs::{BytesInput, HasTargetBytes, UsesInput},
    monitors::MultiMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasMetadata, StdState},
};
pub use libafl_targets::{edges_map_mut_slice, MAX_EDGES_NUM};
use unicorn_engine::{
    unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE},
    RegisterARM64,
};

use crate::{
    emu::harness,
    helper::{hash_me, memory_dump},
    hooks::block_hook,
};

// emulating

fn main() {
    let timeout = Duration::from_secs(1);

    let monitor = MultiMonitor::new(|s| println!("{s}"));
    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    let edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            edges_map_mut_slice(),
            addr_of_mut!(MAX_EDGES_NUM),
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

    let mut binding = harness; // being harness a function we need a local var to bind it
    let executor = InProcessExecutor::new(
        &mut binding,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the executor");

    let mut executor = TimeoutExecutor::new(executor, timeout);

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

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
