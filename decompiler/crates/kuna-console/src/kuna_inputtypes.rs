//! Decompile one function with caller-stated parameter types, each found by
//! its storage at entry ([`ConsoleProgram::decompile_with_input_types`]).
//!
//! The `type` directive binds a parameter by the name the previous decompile
//! printed; this binds it by its storage at entry (a register or stack slot
//! fixed by the ABI), through the directive's own two passes: the first finds
//! the parameter Symbol whose storage matches, the retype goes through the
//! same path as `type a0 <decl>` (so the other parameters are kept, not
//! dropped as a locked prototype would drop them), and the second decompiles
//! with the changed scope carried across. Nothing
//! is left on the program: the next decompile without inputs prints what it
//! printed before.
//!
//! [`ConsoleProgram::decompile_with_input_and_local_types`] also retypes
//! locals. The caller reads a pass's function and names each local as that
//! pass printed it; each retype goes through the `type` directive's path.
//! That pass already has the parameter types, since a parameter's type can
//! re-lay the locals; with both kinds of input applied, this costs one pass
//! more.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_base::types::{int4, uint4};
use kuna_decomp::architecture::Architecture;
use kuna_decomp::database::symbol_category;
use kuna_decomp::dtype::Datatype;
use kuna_decomp::fspec::ParameterPieces;
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

/// Names the locals to retype in a first pass's function, as that pass
/// printed them, each with its type
/// ([`ConsoleProgram::decompile_with_input_and_local_types`]).
pub type LocalTypes<'a> = dyn FnMut(&mut Architecture, &Funcdata) -> Vec<(String, Rc<Datatype>)> + 'a;

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
        self.decompile_inputs(entry, inputs, None).map(|(fd, outcomes, _)| (fd, outcomes))
    }

    /// [`ConsoleProgram::decompile_with_input_types`] that also retypes locals.
    /// `locals` reads a pass's function (it may print it with the architecture
    /// it is given) and names each local to retype as the pass printed it, with
    /// its type. That pass has the applied inputs' parameter types, so it names
    /// the locals the returned function has where no local is retyped. Each is
    /// applied as the `type` directive applies `type <name> <decl>` on that
    /// output, so a register local takes a type of its own width, and a
    /// structure, union or array may grow a stack local over the frame, over
    /// the locals beside it. The function comes back with the inputs' outcomes
    /// and one outcome per local `locals` named, in its order. A local is
    /// rejected for the reason the directive would give, or when `locals`
    /// names it twice.
    ///
    /// Without an input applied, `locals` reads the first pass, and a second
    /// runs only if a local is retyped. With one applied, `locals` reads the
    /// second pass, and a third runs only if a local is retyped.
    pub fn decompile_with_input_and_local_types(
        &mut self,
        entry: &FunctionEntry,
        inputs: &[(Address, Rc<Datatype>)],
        locals: &mut LocalTypes<'_>,
    ) -> KunaResult<(Funcdata, Vec<InputTypeOutcome>, Vec<InputTypeOutcome>)> {
        self.decompile_inputs(entry, inputs, Some(locals))
    }

    fn decompile_inputs(
        &mut self,
        entry: &FunctionEntry,
        inputs: &[(Address, Rc<Datatype>)],
        locals: Option<&mut LocalTypes<'_>>,
    ) -> KunaResult<(Funcdata, Vec<InputTypeOutcome>, Vec<InputTypeOutcome>)> {
        let _load = self.arch().load_scope();
        self.forget_synthesized_structs()?;
        let vma = entry.addr.get_offset();
        let mapped = self.dwarf_locals_for(vma);
        let declared = self.declared_extent(vma);
        let flow = self.noreturn_flow_overrides(&entry.addr);
        let replay = !inputs.is_empty() || locals.is_some();
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
        let mut local_outcomes = Vec::new();
        let mut params = Vec::new();
        let mut relaid = false;
        if let Some(locals) = locals {
            // A parameter's type can re-lay the locals, so `locals` reads a pass
            // that already has the parameter types: the C the last pass prints
            // where no local is retyped.
            if outcomes.contains(&InputTypeOutcome::Applied) {
                params = crate::kuna_paramasserts::carried(&fd, &[]);
                fd = self.decompile_carried(entry, declared, &flow, fd, &params, true)?;
                relaid = true;
            }
            let named = locals(self.arch_mut(), &fd);
            let maxduplicates = kuna_decomp::kuna_dynamichashmax::MAX_DUPLICATES;
            for (i, (name, ct)) in named.iter().enumerate() {
                let outcome = if named[..i].iter().any(|(earlier, _)| earlier == name) {
                    Err(format!("Another input already types {name}"))
                } else {
                    crate::kuna_hightarget::apply_local(&mut fd, name, "", Some(Rc::clone(ct)), maxduplicates, Some(self.arch()))
                        .map(|_| ())
                };
                local_outcomes.push(match outcome {
                    Ok(()) => InputTypeOutcome::Applied,
                    Err(reason) => InputTypeOutcome::Rejected(reason),
                });
            }
        }
        let retyped_locals = local_outcomes.contains(&InputTypeOutcome::Applied);
        if !outcomes.contains(&InputTypeOutcome::Applied) && !retyped_locals {
            return Ok((fd, outcomes, local_outcomes));
        }
        if !relaid || retyped_locals {
            let params = crate::kuna_paramasserts::carried(&fd, &params);
            fd = self.decompile_carried(entry, declared, &flow, fd, &params, false)?;
        }

        for ((storage, ct), outcome) in inputs.iter().zip(outcomes.iter_mut()) {
            if *outcome == InputTypeOutcome::Applied && !has_parameter(&fd, storage, ct) {
                *outcome = InputTypeOutcome::Rejected(format!(
                    "The decompile kept no parameter of this type in {}",
                    storage_name(self.arch(), storage, ct)
                ));
            }
        }
        Ok((fd, outcomes, local_outcomes))
    }

    /// Decompile `entry` again with what the directives applied to `fd` (the
    /// pass before) carried across, and `params` as its parameters. With
    /// `record`, the pass records its names, so a further pass may follow.
    fn decompile_carried(
        &mut self,
        entry: &FunctionEntry,
        declared: int4,
        flow: &[(Address, uint4)],
        fd: Funcdata,
        params: &[(int4, String, ParameterPieces)],
        record: bool,
    ) -> KunaResult<Funcdata> {
        let carried = crate::assertions::carried_symbols(&fd);
        let carried_usepoint = crate::assertions::carried_usepoint_symbols(&fd);
        let carried_dynamic = crate::assertions::carried_dynamic_symbols(&fd);
        let carried_objects = kuna_decomp::kuna_stackobjectasserts::specs(&fd).to_vec();
        self.arch_mut().kuna_prior_names = kuna_decomp::kuna_stablenames::carry(&fd);
        self.arch_mut().kuna_record_names = record;
        drop(fd);
        let next = decompile_one(
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
                flow_overrides: flow,
                mapped_params: params,
            },
            &[],
        )
        .result;
        self.arch_mut().kuna_prior_names = Default::default();
        self.arch_mut().kuna_record_names = false;
        next
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
