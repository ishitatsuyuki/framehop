pub mod binary;
pub mod converter;
/// SFrame (Simple Frame) format support for x86_64
///
/// This module provides conversion from framehop's UnwindRuleX86_64 to
/// SFrame Frame Row Entries (FRE), which describe stack unwinding information
/// in a simple, fast format suitable for production profiling.
pub mod types;

pub use binary::{serialize_sframe, SFrameError};
pub use converter::{convert_unwind_rule, ConversionResult};
pub use types::{CfaBaseReg, FpTracking, FrameRowEntry, FunctionDescriptor};
