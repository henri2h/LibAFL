use std::{cell::UnsafeCell, cmp::max};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::UsesInput, state::HasMetadata};
pub use libafl_targets::{edges_max_num, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE, MAX_EDGES_NUM};
use unicorn_engine::{
    unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE},
    RegisterARM64,
};

use crate::helper::hash_me;

static mut PREV_LOC: u64 = 0;

pub fn block_hook(emu: &mut unicorn_engine::Unicorn<()>, address: u64, small: u32) {
    //println!("Block hook: address: {:X} {}", address, small);

    unsafe {
        let hash = (address ^ PREV_LOC) & (EDGES_MAP_SIZE as u64 - 1);
        // println!("Hash {}", hash);
        EDGES_MAP[hash as usize] += 1;
        PREV_LOC = address >> 1;
    }
}
