//! Decompile one function with caller-stated parameter types, each found by
//! its storage at entry ([`ConsoleProgram::decompile_with_input_types`]).
//!
//! A caller that tracks parameters by storage (a register or stack slot fixed
//! by the ABI) cannot use the `type` directive, which binds a parameter by the
//! name the previous decompile printed. This runs the directive's own two
//! passes: the first finds the parameter Symbol whose storage matches, the
//! retype goes through the same path as `type a0 <decl>` (so the other
//! parameters are kept, not dropped as a locked prototype would drop them),
//! and the second decompiles with the changed scope carried across. Nothing
//! is left on the program: the next decompile without inputs prints what it
//! printed before.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_base::types::uint4;
use kuna_decomp::architecture::Architecture;
use kuna_decomp::database::symbol_category;
use kuna_decomp::dtype::Datatype;
use kuna_decomp::funcdata::Funcdata;

use crate::decompile_step::{decompile_one, DecompileSeed};
use crate::engine::{ConsoleProgram, FunctionEntry};

/// What became of one input type given to
/// [`ConsoleProgram::decompile_with_input_types`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputTypeOutcome {
    /// The parameter in that storage has the type in the returned function.
    Applied,
    /// The type was not applied, for the reason given.
    Rejected(String),
}

impl ConsoleProgram {
    /// Decompile `entry` with each `(storage, type)` input retyping the
    /// parameter that lives in `storage` at entry, keeping the other
    /// parameters, and return the function with one outcome per input, in
    /// order. An input is rejected when no parameter lives in its storage,
    /// when its type's width differs from the parameter's, or when another
    /// input names the same storage. With no input applied, the function is
    /// decompiled once, as the whole-binary loop decompiles it. With
    /// [`ConsoleProgram::set_local_synthesized_structs`] on, it first destroys
    /// the structures earlier decompiles guessed.
    pub fn decompile_with_input_types(
        &mut self,
        entry: &FunctionEntry,
        inputs: &[(Address, Rc<Datatype>)],
    ) -> KunaResult<(Funcdata, Vec<InputTypeOutcome>)> {
        let _load = self.arch().load_scope();
        self.forget_synthesized_structs()?;
        let vma = entry.addr.get_offset();
        let mapped = self.dwarf_locals_for(vma);
        let declared = self.declared_extent(vma);
        let flow = self.noreturn_flow_overrides(&entry.addr);
        let replay = !inputs.is_empty();
        self.arch_mut().kuna_record_names = replay;
        let first = decompile_one(
            self.arch_mut(),
            &entry.name,
            entry.addr.clone(),
            declared,
            &DecompileSeed::plain(&mapped, &flow),
            &[],
        )
        .result;
        self.arch_mut().kuna_record_names = false;
        let mut fd = first?;

        let mut outcomes = Vec::with_capacity(inputs.len());
        for (i, (storage, ct)) in inputs.iter().enumerate() {
            let outcome = if inputs[..i].iter().any(|(earlier, _)| earlier == storage) {
                Err(format!("Another input already types {}", storage_name(self.arch(), storage, ct)))
            } else {
                retype_at(self.arch(), &mut fd, storage, ct)
            };
            outcomes.push(match outcome {
                Ok(()) => InputTypeOutcome::Applied,
                Err(reason) => InputTypeOutcome::Rejected(reason),
            });
        }
        if !outcomes.contains(&InputTypeOutcome::Applied) {
            return Ok((fd, outcomes));
        }

        let carried = crate::assertions::carried_symbols(&fd);
        let carried_usepoint = crate::assertions::carried_usepoint_symbols(&fd);
        let carried_dynamic = crate::assertions::carried_dynamic_symbols(&fd);
        let carried_objects = kuna_decomp::kuna_stackobjectasserts::specs(&fd).to_vec();
        let carried_params = crate::kuna_paramasserts::carried(&fd, &[]);
        self.arch_mut().kuna_prior_names = kuna_decomp::kuna_stablenames::carry(&fd);
        drop(fd);
        let second = decompile_one(
            self.arch_mut(),
            &entry.name,
            entry.addr.clone(),
            declared,
            &DecompileSeed {
                purpose: kuna_decomp::decompile_drive::DrivePurpose::Batch,
                mapped_symbols: &carried,
                usepoint_symbols: &carried_usepoint,
                dynamic_symbols: &carried_dynamic,
                object_assertions: &carried_objects,
                pending_proto: None,
                flow_overrides: &flow,
                mapped_params: &carried_params,
            },
            &[],
        )
        .result;
        self.arch_mut().kuna_prior_names = Default::default();
        let fd = second?;

        for ((storage, ct), outcome) in inputs.iter().zip(outcomes.iter_mut()) {
            if *outcome == InputTypeOutcome::Applied && !has_parameter(&fd, storage, ct) {
                *outcome = InputTypeOutcome::Rejected(format!(
                    "The decompile kept no parameter of this type in {}",
                    storage_name(self.arch(), storage, ct)
                ));
            }
        }
        Ok((fd, outcomes))
    }

    /// The `CALL_RETURN` flow overrides the whole-binary loop seeds at the
    /// image's `call error(nonzero, ...)` sites, in `entry`'s space.
    pub(crate) fn noreturn_flow_overrides(&self, entry: &Address) -> Vec<(Address, uint4)> {
        match entry.get_space() {
            Some(space) => self
                .arch()
                .error_noreturn_callsites
                .iter()
                .map(|&off| (Address::new(Rc::clone(space), off), kuna_decomp::overrides::flow_type::CALL_RETURN))
                .collect(),
            None => Vec::new(),
        }
    }
}

/// Retype the parameter Symbol whose storage starts at `storage`, as the
/// `type` directive retypes one it found by name.
fn retype_at(arch: &Architecture, fd: &mut Funcdata, storage: &Address, ct: &Rc<Datatype>) -> Result<(), String> {
    let scope = fd.get_scope_local().ok_or("Function has no local scope")?;
    let symbol = scope
        .named_symbol_storage()
        .into_iter()
        .find(|(symbol, at, ..)| at == storage && scope.symbol_category(*symbol) == symbol_category::FUNCTION_PARAMETER)
        .map(|(symbol, ..)| symbol)
        .ok_or_else(|| format!("No parameter in {}", storage_name(arch, storage, ct)))?;
    crate::kuna_hightarget::apply_symbol(fd, symbol, "", Some(Rc::clone(ct))).map(|_| ())
}

/// Does `fd`'s prototype have a parameter in `storage` typed `ct`?
fn has_parameter(fd: &Funcdata, storage: &Address, ct: &Rc<Datatype>) -> bool {
    let proto = fd.get_func_proto();
    (0..proto.num_params()).filter_map(|slot| proto.get_param(slot)).any(|parameter| {
        parameter.get_address() == *storage
            && parameter
                .get_type()
                .is_some_and(|ty| Rc::ptr_eq(ty, ct) || ty.compare(ct, 10).is_ok_and(|order| order == 0))
    })
}

/// The register `storage` names at `ct`'s width, a stack slot as its signed
/// offset from the stack pointer at entry (`stack+0x4`), else its raw address.
fn storage_name(arch: &Architecture, storage: &Address, ct: &Rc<Datatype>) -> String {
    let stack = arch.manage().get_stack_space();
    if let (Some(space), Some(stack)) = (storage.get_space(), stack) {
        if space.get_index() == stack.get_index() {
            let bits = (stack.get_addr_size() * 8) as i32;
            let offset = kuna_base::address::sign_extend(storage.get_offset() as i64, bits - 1);
            let sign = if offset < 0 { '-' } else { '+' };
            return format!("stack{sign}0x{:x}", offset.unsigned_abs());
        }
    }
    let register = storage
        .get_space()
        .map(|space| arch.translate().get_register_name(space, storage.get_offset(), ct.get_size()))
        .unwrap_or_default();
    if !register.is_empty() {
        return register;
    }
    let mut raw = String::new();
    match storage.print_raw(&mut raw) {
        Ok(()) => raw,
        Err(_) => format!("0x{:x}", storage.get_offset()),
    }
}
