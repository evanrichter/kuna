//! (kuna) Load-time options: the settings the loader, the analysis tier and the
//! architecture build read before any `option` command can run.
//!
//! A library caller fills a [`LoadOptions`] and passes it to a bootstrap that
//! takes one (`kuna_console::engine::bootstrap_from_object_with_options`). The
//! bootstrap enters a [`LoadScope`] on the loading thread, the gates read the
//! options through [`scoped`], and the new `Architecture` keeps a copy, so the
//! analysis commit and every later decompile of that program read the same
//! values. Nothing on that path reads or writes the process environment, so two
//! images can load at once with different settings.
//!
//! The environment is the CLI's channel: the `kuna` CLI exports each
//! `--option` gate onto the `decomp_dbg` subprocess, and the console's
//! `load file` turns it back into options with [`LoadOptions::from_env`]. A
//! gate read outside any scope falls back to its environment variable, which
//! keeps every older entry point behaving as before.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

use crate::kuna_libctypes::LibcTypesLayout;
use crate::kuna_ppc32picimports::Mode as Ppc32PicMode;
use crate::kuna_sourcelang::SourceLang;
use crate::kuna_symbolnamechars::NameChars;
use crate::options::env_toggle;

/// The `--slice` fat Mach-O slice override.
pub const MACHO_SLICE_ENV: &str = "KUNA_MACHO_SLICE";
/// The arm64e Apple-Silicon spec gate.
pub const MACHO_ARM64E_ENV: &str = "KUNA_MACHO_ARM64E";
/// The external `.pdb` file to apply.
pub const PDB_PATH_ENV: &str = "kuna_pdb_path";
/// The external `.fid` function-ID database to apply.
pub const FID_DB_ENV: &str = "kuna_fid_db";

/// Every load-time setting, one field per option. [`Default`] is the shipped
/// default of each option, the value an unset environment variable means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadOptions {
    /// `relocobjects`: load ET_REL objects with their sections laid out.
    pub relocobjects: bool,
    /// `ppc32picimports`; only `abi` acts at load time.
    pub ppc32picimports: Ppc32PicMode,
    /// `i386_pie_plt`: decode i386 PIE PLT stubs.
    pub i386_pie_plt: bool,
    /// `ifuncfpret`: name x86-64 IFUNC PLT stubs.
    pub ifuncfpret: bool,
    /// `relocrebase`: rebase relocatable objects for analysis.
    pub relocrebase: bool,
    /// `dynrelocs`: apply a linked image's dynamic relocations.
    pub dynrelocs: bool,
    /// `pdatachained`: drop chained-UNWIND_INFO `.pdata` entries.
    pub pdatachained: bool,
    /// `rexthunk`: reject REX-prefixed x86-64 PE import thunks.
    pub rexthunk: bool,
    /// `goabi`: select the golang compiler spec for a Go image.
    pub goabi: bool,
    /// `goreg`: name and type the goroutine register.
    pub goreg: bool,
    /// `peordinal`: name PE imports by ordinal.
    pub peordinal: bool,
    /// `msvcfpconst`: recover MSVC `__real@` floating-point constants.
    pub msvcfpconst: bool,
    /// `symbolnamerepair`: skip empty scope components in symbol names.
    pub symbolnamerepair: bool,
    /// `symbolnamechars`: how symbol-name characters are sanitized.
    pub symbolnamechars: NameChars,
    /// `symbolnamebound`: the scope-component ceiling, `None` for unbounded.
    pub symbolnamebound: Option<usize>,
    /// `typedepth`: full-depth DWARF type resolution.
    pub typedepth: bool,
    /// `libctypes`: the named libc aggregate types.
    pub libctypes: LibcTypesLayout,
    /// `dwarfstructs`: import DWARF aggregate layouts.
    pub dwarfstructs: bool,
    /// `gotypes`: harvest Go runtime types.
    pub gotypes: bool,
    /// `dwarfvariants`: import DWARF variant parts.
    pub dwarfvariants: bool,
    /// `variantnames`: name variant discriminant values.
    pub variantnames: bool,
    /// `calltargettype`: give DWARF function pointers their prototypes.
    pub calltargettype: bool,
    /// `macho-arm64e`: select the Apple-Silicon spec for an arm64e Mach-O.
    pub macho_arm64e: bool,
    /// `sourcelang`: force the source language; `None` trusts detection.
    pub sourcelang: Option<SourceLang>,
    /// `swiftdemangle`: demangle Swift symbols.
    pub swiftdemangle: bool,
    /// The fat Mach-O slice to load (`--slice`); `None` takes the default.
    pub macho_slice: Option<String>,
    /// An external `.pdb` file to apply.
    pub pdb_path: Option<PathBuf>,
    /// An external `.fid` function-ID database to apply.
    pub fid_db: Option<PathBuf>,
    /// The Go toolchain release, which picks the `runtime.g` layout. The
    /// bootstrap takes it from the image's build info, else from here.
    pub go_version: Option<(u16, u16)>,
}

impl Default for LoadOptions {
    fn default() -> Self {
        LoadOptions {
            relocobjects: true,
            ppc32picimports: Ppc32PicMode::Off,
            i386_pie_plt: true,
            ifuncfpret: false,
            relocrebase: true,
            dynrelocs: true,
            pdatachained: true,
            rexthunk: true,
            goabi: true,
            goreg: true,
            peordinal: true,
            msvcfpconst: true,
            symbolnamerepair: true,
            symbolnamechars: NameChars::default(),
            symbolnamebound: Some(crate::kuna_symbolnamebound::DEFAULT_SCOPE_DEPTH),
            typedepth: true,
            libctypes: LibcTypesLayout::Opaque,
            dwarfstructs: true,
            gotypes: true,
            dwarfvariants: true,
            variantnames: true,
            calltargettype: false,
            macho_arm64e: false,
            sourcelang: None,
            swiftdemangle: true,
            macho_slice: None,
            pdb_path: None,
            fid_db: None,
            go_version: None,
        }
    }
}

impl LoadOptions {
    /// The options the environment states, in the vocabulary the CLI exports.
    /// An unset or unrecognized variable leaves that option at its default.
    pub fn from_env() -> Self {
        LoadOptions {
            relocobjects: env::relocobjects(),
            ppc32picimports: env::ppc32picimports(),
            i386_pie_plt: env::i386_pie_plt(),
            ifuncfpret: env::ifuncfpret(),
            relocrebase: env::relocrebase(),
            dynrelocs: env::dynrelocs(),
            pdatachained: env::pdatachained(),
            rexthunk: env::rexthunk(),
            goabi: env::goabi(),
            goreg: env::goreg(),
            peordinal: env::peordinal(),
            msvcfpconst: env::msvcfpconst(),
            symbolnamerepair: env::symbolnamerepair(),
            symbolnamechars: env::symbolnamechars(),
            symbolnamebound: env::symbolnamebound(),
            typedepth: env::typedepth(),
            libctypes: env::libctypes(),
            dwarfstructs: env::dwarfstructs(),
            gotypes: env::gotypes(),
            dwarfvariants: env::dwarfvariants(),
            variantnames: env::variantnames(),
            calltargettype: env::calltargettype(),
            macho_arm64e: env::macho_arm64e(),
            sourcelang: env::sourcelang(),
            swiftdemangle: env::swiftdemangle(),
            macho_slice: env::macho_slice(),
            pdb_path: env::pdb_path(),
            fid_db: env::fid_db(),
            go_version: None,
        }
    }

    /// The options in force on this thread: the innermost scope's, else the
    /// environment's.
    pub fn in_force() -> Rc<LoadOptions> {
        CURRENT
            .with(|current| current.borrow().clone())
            .unwrap_or_else(|| {
                FALLBACKS.with(|count| count.set(count.get() + 1));
                Rc::new(LoadOptions::from_env())
            })
    }

    /// Make these the options in force on this thread until the scope drops.
    pub fn enter(&self) -> LoadScope {
        enter(Rc::new(self.clone()))
    }

    /// Write the named option's value to the environment variable a later
    /// `load file` in this process reads. The console calls this after an
    /// `option` command so the choice outlives the program it was set on; a
    /// library never needs it. A name that is not a load-time option is
    /// ignored.
    pub fn export_env(&self, option: &str) {
        use crate::*;
        match option {
            "relocobjects" => std::env::set_var(
                crate::options::RELOC_OBJECTS_ENV,
                if self.relocobjects { "1" } else { "0" },
            ),
            "ppc32picimports" => self.ppc32picimports.set_env(),
            "i386_pie_plt" => kuna_i386_pie_plt::set_i386_pie_plt_env(self.i386_pie_plt),
            "ifuncfpret" => kuna_ifuncfpret::set_ifuncfpret_env(self.ifuncfpret),
            "relocrebase" => kuna_relocrebase::set_relocrebase_env(self.relocrebase),
            "dynrelocs" => kuna_dynrelocs::set_dynrelocs_env(self.dynrelocs),
            "pdatachained" => kuna_pdatachained::set_pdatachained_env(self.pdatachained),
            "rexthunk" => kuna_rexthunk::set_rexthunk_env(self.rexthunk),
            "goabi" => kuna_goabi::set_goabi_env(self.goabi),
            "goreg" => kuna_goreg::set_goreg_env(self.goreg),
            "peordinal" => kuna_peordinal::set_peordinal_env(self.peordinal),
            "msvcfpconst" => kuna_msvcfpconst::set_msvcfpconst_env(self.msvcfpconst),
            "symbolnamerepair" => {
                kuna_symbolnamerepair::set_symbolnamerepair_env(self.symbolnamerepair)
            }
            "symbolnamechars" => {
                kuna_symbolnamechars::set_symbolnamechars_env(self.symbolnamechars)
            }
            "symbolnamebound" => {
                kuna_symbolnamebound::set_symbolnamebound_env(self.symbolnamebound)
            }
            "typedepth" => kuna_typedepth::set_typedepth_env(self.typedepth),
            "libctypes" => kuna_libctypes::set_libctypes_env_layout(self.libctypes),
            "dwarfstructs" => kuna_dwarfstructs::set_dwarfstructs_env(self.dwarfstructs),
            "gotypes" => kuna_gotypes::set_gotypes_env(self.gotypes),
            "dwarfvariants" => kuna_dwarfvariants::set_dwarfvariants_env(self.dwarfvariants),
            "variantnames" => kuna_variantnames::set_variantnames_env(self.variantnames),
            "sourcelang" => kuna_sourcelang::set_sourcelang_env(self.sourcelang),
            "swiftdemangle" => kuna_swiftdemangle::set_swiftdemangle_env(self.swiftdemangle),
            _ => {}
        }
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<LoadOptions>>> = const { RefCell::new(None) };
    static FALLBACKS: Cell<u64> = const { Cell::new(0) };
}

/// Make `options` the options in force on this thread until the scope drops.
pub fn enter(options: Rc<LoadOptions>) -> LoadScope {
    let previous = CURRENT.with(|current| current.replace(Some(options)));
    LoadScope { previous }
}

/// `read` applied to the options in force on this thread, or `None` outside
/// every scope (the caller then reads its environment variable).
pub fn scoped<T>(read: impl FnOnce(&LoadOptions) -> T) -> Option<T> {
    let read = CURRENT.with(|current| current.borrow().as_deref().map(read));
    if read.is_none() {
        FALLBACKS.with(|count| count.set(count.get() + 1));
    }
    read
}

/// How many reads of the options on this thread found no scope in force and
/// fell back to the environment. A caller that loads with explicit options can check that
/// its calls leave this unchanged.
pub fn environment_fallbacks() -> u64 {
    FALLBACKS.with(Cell::get)
}

/// Restores the enclosing options when dropped. Scopes nest, and each belongs
/// to the thread that entered it.
#[must_use = "the options leave force when the scope drops"]
pub struct LoadScope {
    previous: Option<Rc<LoadOptions>>,
}

impl Drop for LoadScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CURRENT.with(|current| *current.borrow_mut() = previous);
    }
}

/// Each option read from its environment variable, in the vocabulary the CLI
/// exports: the fallback a gate takes outside every scope.
pub mod env {
    use super::*;

    fn path(name: &str) -> Option<PathBuf> {
        std::env::var_os(name)
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
    }

    pub fn relocobjects() -> bool {
        match std::env::var(crate::options::RELOC_OBJECTS_ENV) {
            Ok(v) => !matches!(v.trim(), "0" | "off" | "false" | "no" | "OFF"),
            Err(_) => true,
        }
    }

    pub fn ppc32picimports() -> Ppc32PicMode {
        std::env::var(crate::kuna_ppc32picimports::ENV).map_or(Ppc32PicMode::Off, |value| {
            Ppc32PicMode::from_env_value(&value)
        })
    }

    pub fn i386_pie_plt() -> bool {
        env_toggle(crate::kuna_i386_pie_plt::I386_PIE_PLT_ENV, true)
    }

    pub fn ifuncfpret() -> bool {
        env_toggle(crate::kuna_ifuncfpret::IFUNCFPRET_ENV, false)
    }

    pub fn relocrebase() -> bool {
        env_toggle(crate::kuna_relocrebase::RELOCREBASE_ENV, true)
    }

    pub fn dynrelocs() -> bool {
        env_toggle(crate::kuna_dynrelocs::DYNRELOCS_ENV, true)
    }

    pub fn pdatachained() -> bool {
        env_toggle(crate::kuna_pdatachained::PDATACHAINED_ENV, true)
    }

    pub fn rexthunk() -> bool {
        env_toggle(crate::kuna_rexthunk::REXTHUNK_ENV, true)
    }

    pub fn goabi() -> bool {
        env_toggle(crate::kuna_goabi::GOABI_ENV, true)
    }

    pub fn goreg() -> bool {
        env_toggle(crate::kuna_goreg::GOREG_ENV, true)
    }

    pub fn peordinal() -> bool {
        env_toggle(crate::kuna_peordinal::PEORDINAL_ENV, true)
    }

    pub fn msvcfpconst() -> bool {
        env_toggle(crate::kuna_msvcfpconst::MSVCFPCONST_ENV, true)
    }

    pub fn symbolnamerepair() -> bool {
        env_toggle(crate::kuna_symbolnamerepair::SYMBOLNAMEREPAIR_ENV, true)
    }

    pub fn symbolnamechars() -> NameChars {
        match std::env::var(crate::kuna_symbolnamechars::SYMBOLNAMECHARS_ENV) {
            Ok(v) => NameChars::parse(&v).unwrap_or_default(),
            Err(_) => NameChars::default(),
        }
    }

    pub fn symbolnamebound() -> Option<usize> {
        use crate::kuna_symbolnamebound::{
            parse_bound_token, DEFAULT_SCOPE_DEPTH, SYMBOLNAMEBOUND_ENV,
        };
        match std::env::var(SYMBOLNAMEBOUND_ENV) {
            Ok(v) => parse_bound_token(v.trim()).unwrap_or(Some(DEFAULT_SCOPE_DEPTH)),
            Err(_) => Some(DEFAULT_SCOPE_DEPTH),
        }
    }

    pub fn typedepth() -> bool {
        env_toggle(crate::kuna_typedepth::TYPEDEPTH_ENV, true)
    }

    pub fn libctypes() -> LibcTypesLayout {
        match std::env::var(crate::kuna_libctypes::LIBCTYPES_ENV) {
            Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "false" => LibcTypesLayout::Off,
                "glibc" => LibcTypesLayout::Glibc,
                _ => LibcTypesLayout::Opaque,
            },
            Err(_) => LibcTypesLayout::Opaque,
        }
    }

    pub fn dwarfstructs() -> bool {
        env_toggle(crate::kuna_dwarfstructs::DWARFSTRUCTS_ENV, true)
    }

    pub fn gotypes() -> bool {
        env_toggle(crate::kuna_gotypes::GOTYPES_ENV, true)
    }

    pub fn dwarfvariants() -> bool {
        env_toggle(crate::kuna_dwarfvariants::DWARFVARIANTS_ENV, true)
    }

    pub fn variantnames() -> bool {
        env_toggle(crate::kuna_variantnames::VARIANTNAMES_ENV, true)
    }

    pub fn calltargettype() -> bool {
        env_toggle(crate::kuna_calltargettype::CALLTARGETTYPE_ENV, false)
    }

    pub fn macho_arm64e() -> bool {
        std::env::var_os(MACHO_ARM64E_ENV).is_some_and(|v| !v.is_empty())
    }

    pub fn sourcelang() -> Option<SourceLang> {
        SourceLang::parse_forced(&std::env::var(crate::kuna_sourcelang::SOURCELANG_ENV).ok()?)
    }

    pub fn swiftdemangle() -> bool {
        env_toggle(crate::kuna_swiftdemangle::SWIFTDEMANGLE_ENV, true)
    }

    pub fn macho_slice() -> Option<String> {
        std::env::var(MACHO_SLICE_ENV)
            .ok()
            .filter(|t| !t.trim().is_empty())
    }

    pub fn pdb_path() -> Option<PathBuf> {
        path(PDB_PATH_ENV)
    }

    pub fn fid_db() -> Option<PathBuf> {
        path(FID_DB_ENV)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_nest_and_restore_per_thread() {
        assert_eq!(scoped(|o| o.goabi), None);
        let outer = LoadOptions {
            goabi: false,
            ..LoadOptions::default()
        };
        let _outer = outer.enter();
        assert_eq!(scoped(|o| o.goabi), Some(false));
        {
            let _inner = LoadOptions::default().enter();
            assert_eq!(scoped(|o| o.goabi), Some(true));
            std::thread::spawn(|| assert_eq!(scoped(|o| o.goabi), None))
                .join()
                .unwrap();
        }
        assert_eq!(scoped(|o| o.goabi), Some(false));
        assert!(!LoadOptions::in_force().goabi);
    }

    #[test]
    fn a_scope_restores_the_enclosing_options_after_a_panic() {
        let _outer = LoadOptions {
            dynrelocs: false,
            ..LoadOptions::default()
        }
        .enter();
        let unwound = std::panic::catch_unwind(|| {
            let _inner = LoadOptions::default().enter();
            panic!("load failed");
        });
        assert!(unwound.is_err());
        assert_eq!(scoped(|o| o.dynrelocs), Some(false));
    }

    #[test]
    fn gates_read_the_scope_not_the_environment() {
        let options = LoadOptions {
            dwarfstructs: false,
            ifuncfpret: true,
            symbolnamebound: None,
            symbolnamechars: NameChars::Ident,
            libctypes: LibcTypesLayout::Glibc,
            sourcelang: Some(SourceLang::Rust),
            ppc32picimports: Ppc32PicMode::Abi,
            ..LoadOptions::default()
        };
        let _scope = options.enter();
        assert!(!crate::kuna_dwarfstructs::dwarfstructs_enabled());
        assert!(crate::kuna_ifuncfpret::ifuncfpret_enabled());
        assert_eq!(crate::kuna_symbolnamebound::symbolnamebound_depth(), None);
        assert_eq!(
            crate::kuna_symbolnamechars::symbolnamechars_mode(),
            NameChars::Ident
        );
        assert_eq!(
            crate::kuna_libctypes::libctypes_layout(),
            LibcTypesLayout::Glibc
        );
        assert_eq!(crate::kuna_sourcelang::forced(), Some(SourceLang::Rust));
        assert!(crate::kuna_ppc32picimports::abi_enabled());
    }
}
