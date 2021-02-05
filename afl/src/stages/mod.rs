pub mod mutational;
pub use mutational::StdMutationalStage;

use crate::{
    corpus::Corpus,
    events::EventManager,
    executors::{Executor, HasObservers},
    feedbacks::FeedbacksTuple,
    inputs::Input,
    observers::ObserversTuple,
    state::State,
    tuples::TupleList,
    utils::Rand,
    AflError,
};

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<C, E, EM, FT, I, OT, R>
where
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Run the stage
    fn perform(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        state: &mut State<C, I, R, FT>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), AflError>;
}

pub trait StagesTuple<C, E, EM, FT, I, OT, R>
where
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn perform_all(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        state: &mut State<C, I, R, FT>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), AflError>;
    fn for_each(&self, f: fn(&dyn Stage<C, E, EM, FT, I, OT, R>));
    fn for_each_mut(&mut self, f: fn(&mut dyn Stage<C, E, EM, FT, I, OT, R>));
}

impl<C, E, EM, FT, I, OT, R> StagesTuple<C, E, EM, FT, I, OT, R> for ()
where
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn perform_all(
        &mut self,
        _rand: &mut R,
        _executor: &mut E,
        _state: &mut State<C, I, R, FT>,
        _manager: &mut EM,
        _corpus_idx: usize,
    ) -> Result<(), AflError> {
        Ok(())
    }
    fn for_each(&self, _f: fn(&dyn Stage<C, E, EM, FT, I, OT, R>)) {}
    fn for_each_mut(&mut self, _f: fn(&mut dyn Stage<C, E, EM, FT, I, OT, R>)) {}
}

impl<Head, Tail, EM, E, OT, FT, C, I, R> StagesTuple<C, E, EM, FT, I, OT, R> for (Head, Tail)
where
    Head: Stage<C, E, EM, FT, I, OT, R>,
    Tail: StagesTuple<C, E, EM, FT, I, OT, R> + TupleList,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn perform_all(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        state: &mut State<C, I, R, FT>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), AflError> {
        self.0.perform(rand, executor, state, manager, corpus_idx)?;
        self.1
            .perform_all(rand, executor, state, manager, corpus_idx)
    }

    fn for_each(&self, f: fn(&dyn Stage<C, E, EM, FT, I, OT, R>)) {
        f(&self.0);
        self.1.for_each(f)
    }

    fn for_each_mut(&mut self, f: fn(&mut dyn Stage<C, E, EM, FT, I, OT, R>)) {
        f(&mut self.0);
        self.1.for_each_mut(f)
    }
}
