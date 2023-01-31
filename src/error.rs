use crate::dwarf::DwarfUnwinderError;
use crate::macho::CompactUnwindInfoUnwinderError;
use crate::seh::SehUnwinderError;

/// The error type used in this crate.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("Could not read stack memory at 0x{0:x}")]
    CouldNotReadStack(u64),

    #[error("Frame pointer unwinding moved backwards")]
    FramepointerUnwindingMovedBackwards,

    #[error("Neither the code address nor the stack pointer changed, would loop")]
    DidNotAdvance,

    #[error("Unwinding caused integer overflow")]
    IntegerOverflow,

    #[error("Return address is null")]
    ReturnAddressIsNull,
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwinderError {
    #[error("Compact Unwind Info unwinding failed: {0}")]
    CompactUnwindInfo(#[source] CompactUnwindInfoUnwinderError),

    #[error("DWARF unwinding failed: {0}")]
    Dwarf(#[from] DwarfUnwinderError),

    #[error("SEH unwinding failed: {0}")]
    Seh(#[from] SehUnwinderError),

    #[error("__unwind_info referred to DWARF FDE but we do not have __eh_frame data")]
    NoDwarfData,

    #[error("No unwind data for the module containing the address")]
    NoModuleUnwindData,

    #[error(".eh_frame_hdr was not successful in looking up the address in the table")]
    EhFrameHdrCouldNotFindAddress,

    #[error("Failed to look up the address in the DwarfCfiIndex search table")]
    DwarfCfiIndexCouldNotFindAddress,
}

impl From<CompactUnwindInfoUnwinderError> for UnwinderError {
    fn from(e: CompactUnwindInfoUnwinderError) -> Self {
        match e {
            CompactUnwindInfoUnwinderError::BadDwarfUnwinding(e) => UnwinderError::Dwarf(e),
            e => UnwinderError::CompactUnwindInfo(e),
        }
    }
}
