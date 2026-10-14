//! Array-of-bytes (AoB) scans over PE file sections.
//!
//! Patterns contain whitespace-separated hexadecimal bytes and `?` or `??`
//! wildcards. Signatures are tried in order, and each signature searches
//! sections in header order using [`BoyerMoore`]. Use [`Aob::add_base`] to
//! determine whether to add the module base address to a scan result.
//!
//! # Examples
//!
//! ```no_run
//! use practice_tool_core::aob::{aob_direct, find_aobs, PeFile};
//!
//! let bytes = std::fs::read("game.exe")?;
//! let pe = PeFile::from_bytes(&bytes)?;
//! let patterns = ["48 8b ? ?? 90"];
//! let scans = [aob_direct("example", &patterns, true)];
//! for (name, offset) in find_aobs(&pe, &scans) {
//!     println!("{name}: {offset:#x}");
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub use pelite::PeFile;

use crate::boyer_moore::BoyerMoore;

fn parse_pattern(pattern: &str) -> Option<Vec<Option<u8>>> {
    let pattern = pattern
        .split_whitespace()
        .map(|byte| match byte {
            "?" | "??" => Some(None),
            x => u8::from_str_radix(x, 16).ok().map(Some),
        })
        .collect::<Option<Vec<_>>>()?;
    (!pattern.is_empty()).then_some(pattern)
}

/// Strategies for retrieving addresses or values from AoB scans.
pub trait Aob {
    /// Search PE sections and return the scan name and first resolvable value.
    /// Empty or invalid patterns and matches with unreadable or overflowing
    /// offsets are skipped.
    fn find(&self, pe_file: &PeFile) -> Option<(&str, usize)>;
    /// The AoB name.
    fn name(&self) -> &str;
    /// Whether the consumer should add the module base address to the result.
    fn add_base(&self) -> bool;
}

struct AobScan<'a> {
    name: &'a str,
    aobs: &'a [&'a str],
    add_base: bool,
    address: Address,
}

enum Address {
    Direct,
    Indirect { offset: usize },
    Relative { offset_from_pattern: usize, offset_from_offset: usize },
}

impl Address {
    fn resolve(&self, base: usize, offset: usize, bytes: &[u8]) -> Option<usize> {
        let read = |relative_offset: usize| -> Option<[u8; 4]> {
            bytes.get(offset.checked_add(relative_offset)?..)?.get(..4)?.try_into().ok()
        };
        match *self {
            Self::Direct => base.checked_add(offset),
            Self::Indirect { offset } => Some(u32::from_le_bytes(read(offset)?) as usize),
            Self::Relative { offset_from_pattern, offset_from_offset } => {
                let displacement = i32::from_le_bytes(read(offset_from_pattern)?) as isize;
                base.checked_add(offset)?
                    .checked_add(offset_from_offset)?
                    .checked_add_signed(displacement)
            },
        }
    }
}

impl Aob for AobScan<'_> {
    fn find(&self, pe_file: &PeFile) -> Option<(&str, usize)> {
        self.aobs.iter().find_map(|aob| {
            let needle = parse_pattern(aob)?;
            let searcher = BoyerMoore::new(&needle);

            pe_file
                .section_headers()
                .into_iter()
                .filter_map(|sh| {
                    Some((sh.VirtualAddress as usize, pe_file.get_section_bytes(sh).ok()?))
                })
                .find_map(|(base, bytes)| {
                    let mut start = 0;
                    while let Some(found) = searcher.find(&bytes[start..]) {
                        let offset = start + found;
                        if let Some(value) = self.address.resolve(base, offset, bytes) {
                            return Some((self.name, value));
                        }
                        // The parsed pattern is nonempty, so every match
                        // consumes at least one byte and this stays in bounds.
                        start = offset + 1;
                    }
                    None
                })
        })
    }

    fn name(&self) -> &str {
        self.name
    }

    fn add_base(&self) -> bool {
        self.add_base
    }
}

/// Create a scan that returns the matching signature's relative virtual
/// address.
pub fn aob_direct<'a>(name: &'a str, aobs: &'a [&'a str], add_base: bool) -> Box<dyn Aob + 'a> {
    Box::new(AobScan { name, aobs, add_base, address: Address::Direct })
}

/// Create a scan that reads a little-endian `u32` at `offset` from a match.
pub fn aob_indirect<'a>(
    name: &'a str,
    aobs: &'a [&'a str],
    offset: usize,
    add_base: bool,
) -> Box<dyn Aob + 'a> {
    Box::new(AobScan { name, aobs, add_base, address: Address::Indirect { offset } })
}

/// Create a scan that reads a signed little-endian `i32` displacement at
/// `offset_from_pattern`, then adds the match's relative virtual address and
/// `offset_from_offset` (usually the instruction length).
pub fn aob_indirect_twice<'a>(
    name: &'a str,
    aobs: &'a [&'a str],
    offset_from_pattern: usize,
    offset_from_offset: usize,
    add_base: bool,
) -> Box<dyn Aob + 'a> {
    Box::new(AobScan {
        name,
        aobs,
        add_base,
        address: Address::Relative { offset_from_pattern, offset_from_offset },
    })
}

/// Run scans in order and collect the names and values of successful matches.
pub fn find_aobs<'a>(pe_file: &PeFile, aobs: &'a [Box<dyn Aob + 'a>]) -> Vec<(&'a str, usize)> {
    aobs.iter().filter_map(|aob| aob.find(pe_file)).collect::<Vec<_>>()
}
