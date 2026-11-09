//! Typed operand pieces from SLEIGH's print walk (kuna).
//!
//! [`StructuredAssembly`] carries the same mnemonic and body text as
//! `Translate::print_assembly_into`, plus pieces that tile the body: literal
//! text, registers, constants and addresses. The walk mirrors
//! `Constructor::printBody` and prints every leaf operand with the symbol's own
//! `print`, so the body is byte-identical to the text API; it reads the
//! resolved [`FixedHandle`]s of the operand and of every subtable around it to
//! classify the leaf.

use std::ops::Range;

use kuna_base::error::{KunaError, KunaResult};
use kuna_base::space::{spacetype, AddrSpace};

use crate::context::FixedHandle;
use crate::slghpatexpress::{PatternExpression, PatternValue};
use crate::slghsymbol::{
    Constructor, ConstructorRef, OperandSymbol, SymbolKind, SymbolTable, SymbolType, SymbolWalker,
};

/// One decoded instruction: its text and the typed pieces of its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredAssembly {
    /// The instruction length in bytes.
    pub length: i32,
    /// The mnemonic, exactly as the text API prints it.
    pub mnemonic: String,
    /// The operand text, exactly as the text API prints it.
    pub body: String,
    /// Non-empty pieces in body order; their spans tile `body`.
    pub pieces: Vec<OperandPiece>,
}

impl StructuredAssembly {
    /// The instruction with its whole body as one text piece, for translators
    /// that print text only.
    pub fn text_only(length: i32, mnemonic: String, body: String) -> StructuredAssembly {
        let pieces = if body.is_empty() {
            Vec::new()
        } else {
            vec![OperandPiece {
                span: 0..body.len(),
                operand: None,
                kind: PieceKind::Text,
            }]
        };
        StructuredAssembly {
            length,
            mnemonic,
            body,
            pieces,
        }
    }

    /// The text of `piece` within the body.
    pub fn text(&self, piece: &OperandPiece) -> &str {
        &self.body[piece.span.clone()]
    }
}

/// A run of the body printed by one SLEIGH source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandPiece {
    /// Byte range within [`StructuredAssembly::body`].
    pub span: Range<usize>,
    /// The operand of the instruction's top constructor this piece belongs to
    /// (SLEIGH operand index, not print order); `None` for its literal text.
    pub operand: Option<u32>,
    /// What the piece denotes.
    pub kind: PieceKind,
}

/// What an operand piece denotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceKind {
    /// Literal text: punctuation, size keywords, condition names.
    Text,
    /// A register: its name as printed and its register-space storage.
    Register {
        name: String,
        offset: u64,
        size: u32,
    },
    /// A scalar the instruction encodes.
    Constant { value: i64 },
    /// A memory address: a constant the operand dereferences at a fixed
    /// location, a value computed from the instruction's own address, or a
    /// varnode in a memory space. `code` marks a flow target. `deref` marks an
    /// operand that reads or writes the memory at the address (`[0x3fc8]` in a
    /// load), as against one that uses the address itself (a LEA or ADR value,
    /// a branch target).
    Address {
        space: String,
        offset: u64,
        code: bool,
        deref: bool,
    },
}

struct Frame {
    hand: FixedHandle,
    code: bool,
}

struct PiecePrinter<'t> {
    table: &'t SymbolTable,
    body: String,
    pieces: Vec<OperandPiece>,
    frames: Vec<Frame>,
}

/// Print the body of the instruction at the walker's base state, recording
/// typed pieces. The walker must stand on a context with resolved handles.
pub(crate) fn print_body_pieces(
    ct: &Constructor,
    walker: &mut (impl SymbolWalker + ?Sized),
    table: &SymbolTable,
) -> KunaResult<(String, Vec<OperandPiece>)> {
    let mut printer = PiecePrinter {
        table,
        body: String::new(),
        pieces: Vec::new(),
        frames: Vec::new(),
    };
    printer.body_of(ct, walker)?;
    Ok((printer.body, printer.pieces))
}

impl<'t> PiecePrinter<'t> {
    fn body_of(
        &mut self,
        ct: &Constructor,
        walker: &mut (impl SymbolWalker + ?Sized),
    ) -> KunaResult<()> {
        let flowthru = ct.get_flowthru_index();
        if flowthru != -1 && self.is_subtable_operand(ct, flowthru)? {
            walker.push_operand(flowthru)?;
            let inner = self.table.get_constructor(walker.get_constructor()?)?;
            self.body_of(inner, walker)?;
            walker.pop_operand()?;
            return Ok(());
        }
        let first = ct.get_first_whitespace();
        if first == -1 {
            return Ok(());
        }
        for piece in ct.get_print_pieces().iter().skip(first as usize + 1) {
            self.piece(ct, piece, None, walker)?;
        }
        Ok(())
    }

    fn piece(
        &mut self,
        ct: &Constructor,
        piece: &[u8],
        operand: Option<u32>,
        walker: &mut (impl SymbolWalker + ?Sized),
    ) -> KunaResult<()> {
        if piece.first() != Some(&b'\n') {
            let start = self.body.len();
            self.body.push_str(&String::from_utf8_lossy(piece));
            self.push(start, operand, PieceKind::Text);
            return Ok(());
        }
        let opid = ct.get_operand(i32::from(piece[1]) - i32::from(b'A'))?;
        let opsym = self.symbol(opid)?;
        let SymbolKind::Operand(op) = opsym.kind() else {
            return Err(KunaError::sleigh("print piece names a non-operand symbol"));
        };
        let index = op.get_index();
        let operand = operand.or(Some(index as u32));
        let hand = walker.get_fixed_handle(index)?;
        let triple = op
            .get_defining_symbol()
            .map(|id| self.symbol(id))
            .transpose()?;
        if triple.is_some_and(|t| t.get_type() == SymbolType::Subtable) {
            self.frames.push(Frame {
                hand,
                code: op.is_code_address(),
            });
            walker.push_operand(index)?;
            let inner = self.table.get_constructor(walker.get_constructor()?)?;
            for p in inner.get_print_pieces() {
                self.piece(inner, p, operand, walker)?;
            }
            walker.pop_operand()?;
            self.frames.pop();
            return Ok(());
        }
        let start = self.body.len();
        opsym.print(&mut self.body, walker, self.table)?;
        let printed = &self.body[start..];
        let kind = self.classify_leaf(op, triple.map(|t| t.kind()), &hand, printed, walker)?;
        self.push(start, operand, kind);
        Ok(())
    }

    fn classify_leaf(
        &self,
        op: &OperandSymbol,
        triple: Option<&SymbolKind>,
        hand: &FixedHandle,
        printed: &str,
        walker: &(impl SymbolWalker + ?Sized),
    ) -> KunaResult<PieceKind> {
        let code = op.is_code_address() || self.frames.iter().any(|f| f.code);
        let pc_relative = match triple {
            None => match op.get_defining_expression() {
                Some(expr) => self.reads_instruction_address(expr, 0)?,
                None => false,
            },
            Some(SymbolKind::Name(_)) => return Ok(PieceKind::Text),
            Some(SymbolKind::Varnode(_) | SymbolKind::VarnodeList(_)) => {
                return Ok(varnode_kind(hand, printed, code));
            }
            // `inst_start` and kin hand back a location in the code space.
            Some(SymbolKind::Start(_) | SymbolKind::End(_) | SymbolKind::Next2(_)) => {
                return Ok(varnode_kind(hand, printed, code));
            }
            Some(SymbolKind::FlowDest(_) | SymbolKind::FlowRef(_)) => true,
            Some(
                SymbolKind::Value(_)
                | SymbolKind::ValueMap(_)
                | SymbolKind::Context(_)
                | SymbolKind::Epsilon(_),
            ) => false,
            Some(_) => return Ok(PieceKind::Text),
        };
        if !matches!(hand.space.as_deref(), Some(s) if s.get_type() == spacetype::IPTR_CONSTANT) {
            return Ok(PieceKind::Text);
        }
        let value = hand.offset_offset;
        if let Some(kind) = self.dereferenced_address(value, code) {
            return Ok(kind);
        }
        if pc_relative {
            if let Some(space) = walker.get_addr().get_space() {
                return Ok(PieceKind::Address {
                    space: space.get_name().to_string(),
                    offset: space.wrap_offset(value),
                    code,
                    deref: false,
                });
            }
        }
        Ok(PieceKind::Constant {
            value: value as i64,
        })
    }

    /// The innermost memory-space handle around the leaf, when it is a fixed
    /// location at `value`: the operand dereferences the constant. A flow
    /// target's handle names the place to go, not memory to read, so it is no
    /// dereference.
    fn dereferenced_address(&self, value: u64, code: bool) -> Option<PieceKind> {
        for frame in self.frames.iter().rev() {
            let Some(space) = frame.hand.space.as_deref() else {
                continue;
            };
            if !is_memory(space) {
                continue;
            }
            if frame.hand.offset_space.is_some() {
                return None;
            }
            let offset = frame.hand.offset_offset;
            let ws = space.get_word_size();
            if offset == space.wrap_offset(value)
                || offset == space.wrap_offset(AddrSpace::address_to_byte(value, ws))
            {
                return Some(PieceKind::Address {
                    space: space.get_name().to_string(),
                    offset,
                    code,
                    deref: !code,
                });
            }
            return None;
        }
        None
    }

    fn reads_instruction_address(&self, expr: &PatternExpression, depth: u32) -> KunaResult<bool> {
        if depth > 16 {
            return Ok(false);
        }
        Ok(match expr {
            PatternExpression::Value(value) => match value {
                PatternValue::StartInstructionValue(_)
                | PatternValue::EndInstructionValue(_)
                | PatternValue::Next2InstructionValue(_) => true,
                PatternValue::OperandValue(ov) => {
                    let ct = ConstructorRef {
                        table_id: ov.table_id(),
                        ct_id: ov.ct_id(),
                    };
                    let opid = self.table.get_constructor(ct)?.get_operand(ov.index())?;
                    let SymbolKind::Operand(op) = self.symbol(opid)?.kind() else {
                        return Ok(false);
                    };
                    match (op.get_defining_expression(), op.get_defining_symbol()) {
                        (Some(inner), _) => self.reads_instruction_address(inner, depth + 1)?,
                        (None, Some(id)) => matches!(
                            self.symbol(id)?.kind(),
                            SymbolKind::Start(_) | SymbolKind::End(_) | SymbolKind::Next2(_)
                        ),
                        (None, None) => false,
                    }
                }
                _ => false,
            },
            PatternExpression::Plus(b)
            | PatternExpression::Sub(b)
            | PatternExpression::Mult(b)
            | PatternExpression::LeftShift(b)
            | PatternExpression::RightShift(b)
            | PatternExpression::And(b)
            | PatternExpression::Or(b)
            | PatternExpression::Xor(b)
            | PatternExpression::Div(b) => {
                self.reads_instruction_address(b.get_left(), depth + 1)?
                    || self.reads_instruction_address(b.get_right(), depth + 1)?
            }
            PatternExpression::Minus(u) | PatternExpression::Not(u) => {
                self.reads_instruction_address(u.get_unary(), depth + 1)?
            }
        })
    }

    fn is_subtable_operand(&self, ct: &Constructor, index: i32) -> KunaResult<bool> {
        let SymbolKind::Operand(op) = self.symbol(ct.get_operand(index)?)?.kind() else {
            return Ok(false);
        };
        match op.get_defining_symbol() {
            Some(id) => Ok(self.symbol(id)?.get_type() == SymbolType::Subtable),
            None => Ok(false),
        }
    }

    fn symbol(&self, id: u32) -> KunaResult<&'t crate::slghsymbol::SleighSymbol> {
        self.table
            .find_symbol_by_id(id)
            .ok_or_else(|| KunaError::sleigh(format!("symbol id {id} is undefined")))
    }

    fn push(&mut self, start: usize, operand: Option<u32>, kind: PieceKind) {
        let end = self.body.len();
        if end == start {
            return;
        }
        if kind == PieceKind::Text {
            if let Some(last) = self.pieces.last_mut() {
                if last.kind == PieceKind::Text && last.operand == operand && last.span.end == start
                {
                    last.span.end = end;
                    return;
                }
            }
        }
        self.pieces.push(OperandPiece {
            span: start..end,
            operand,
            kind,
        });
    }
}

fn is_memory(space: &AddrSpace) -> bool {
    matches!(
        space.get_type(),
        spacetype::IPTR_PROCESSOR | spacetype::IPTR_SPACEBASE
    ) && space.get_name() != "register"
}

fn varnode_kind(hand: &FixedHandle, printed: &str, code: bool) -> PieceKind {
    match hand.space.as_deref() {
        Some(space) if hand.offset_space.is_none() && space.get_name() == "register" => {
            PieceKind::Register {
                name: printed.to_string(),
                offset: hand.offset_offset,
                size: hand.size,
            }
        }
        // A memory varnode is the operand's storage: it reads or writes there.
        Some(space) if hand.offset_space.is_none() && is_memory(space) => PieceKind::Address {
            space: space.get_name().to_string(),
            offset: hand.offset_offset,
            code,
            deref: !code,
        },
        _ => PieceKind::Text,
    }
}
