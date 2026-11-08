//! (kuna `structsynth`) Keep the structures `structsynth` guesses local to one
//! decompile, for a caller that decompiles single functions in whatever order
//! its user asks for them ([`ConsoleProgram::set_local_synthesized_structs`]).
//!
//! The ledger is program-wide on purpose: `decompile-all` and the project
//! export name one record once across every function that reads it, and
//! `--jobs` replays the serial ledger so every worker agrees on the names. An
//! interactive caller has no such order. Under the program-wide ledger the C of
//! one function names its structure by what the program decompiled before it
//! (`transmit` alone prints `struct_0 *a0`, after `init_request` it prints
//! `struct_1 *a0`), so the same function prints differently from one session
//! to the next, and the factory keeps every structure ever guessed.
//!
//! With the setting on, each [`ConsoleProgram::decompile_with_input_types`]
//! first destroys every `struct_N` minted since the setting was turned on, and
//! every type built on one ([`shard::forget_minted`]), so each decompile meets
//! the factory as it stood then. Structures held when the setting was turned on,
//! and every other named type (a parsed declaration, a caller's own struct),
//! are kept. The structures of the previous decompile live until the next one
//! starts, so a caller can still print the function it was handed.
//!
//! The setting is off by default, which keeps the ledger program-wide.

use kuna_base::error::{KunaError, KunaResult};
use kuna_decomp::kuna_structsynth::shard::{self, AtLoad};

use crate::engine::ConsoleProgram;

impl ConsoleProgram {
    /// Make every later decompile through
    /// [`ConsoleProgram::decompile_with_input_types`] guess its structures
    /// afresh, as on a program that decompiled nothing before it, or (`false`)
    /// return to the program-wide ledger. Turning it on records the `struct_N`
    /// names the program holds now; only structures minted after that are
    /// destroyed.
    pub fn set_local_synthesized_structs(&mut self, on: bool) {
        self.local_structs = on.then(|| AtLoad::of(self.arch().types_impl()));
    }

    /// Destroy the structures minted since
    /// [`ConsoleProgram::set_local_synthesized_structs`] turned the setting on,
    /// and every type built on them. A no-op while it is off.
    pub fn forget_synthesized_structs(&mut self) -> KunaResult<()> {
        match &self.local_structs {
            Some(held) => shard::forget_minted(self.arch().types_impl(), held.held()).map_err(KunaError::lowlevel),
            None => Ok(()),
        }
    }
}
