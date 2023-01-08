pub mod emu;
pub mod helper;
pub mod hooks;

use std::fs::File;
use std::io::Read;

use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};
use unicorn_engine::RegisterARM64;

use std::{cell::UnsafeCell, cmp::max};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::UsesInput, state::HasMetadata};

pub use libafl_targets::{edges_max_num, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE, MAX_EDGES_NUM};

use crate::emu::harness;
use crate::helper::{hash_me, memory_dump};
use crate::hooks::block_hook;

use std::path::PathBuf;
#[cfg(windows)]
use std::ptr::write_volatile;

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{RandPrintablesGenerator, RandBytesGenerator},
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    monitors::MultiMonitor,
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{QueueScheduler, IndexesLenTimeMinimizerScheduler},
    stages::mutational::StdMutationalStage,
    state::StdState,
};

// emulating

fn main() {

    let monitor = MultiMonitor::new(|s| println!("{s}"));
    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    let edges = unsafe { &mut hooks::EDGES_MAP };
    let edges_counter = unsafe { &mut hooks::MAX_EDGES_NUM };
    let edges_observer =
        HitcountsMapObserver::new(VariableMapObserver::new("edges", edges, edges_counter));

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


    let mut hooks =
    QemuHooks::new(emulator, tuple_list!(QemuEdgeCoverageHelper::default()));

let executor = QemuExecutor::new(
    &mut hooks,
    &mut harness,
    tuple_list!(edges_observer, time_observer),
    &mut fuzzer,
    &mut state,
    &mut mgr,
)?;
 // In case the corpus is empty (on first run), reset
 if state.corpus().count() < 1 {
    if self.input_dirs.is_empty() {
        // Generator of printable bytearrays of max size 32
        let mut generator = RandBytesGenerator::new(32);

        // Generate 8 initial inputs
        state
            .generate_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut generator,
                &mut mgr,
                8,
            )
            .expect("Failed to generate the initial corpus");
        println!(
            "We imported {} inputs from the generator.",
            state.corpus().count()
        );
    } else {
        println!("Loading from {:?}", &self.input_dirs);
        // Load from disk
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                self.input_dirs,
            )
            .unwrap_or_else(|_| {
                panic!("Failed to load initial corpus at {:?}", &self.input_dirs);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }
}

let mut executor = TimeoutExecutor::new(executor, timeout);


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
