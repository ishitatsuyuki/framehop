use super::types::{CfaBaseReg, FunctionDescriptor};
/// Binary serialization for SFrame format v2
///
/// This module implements the binary layout specified in the SFrame specification v2.
/// All structures are packed and stored in target endianness (little-endian for x86_64).
use std::io::{self, Write};

/// SFrame magic number (0xdee2)
const SFRAME_MAGIC: u16 = 0xdee2;

/// SFrame version 2
const SFRAME_VERSION: u8 = 2;

/// SFrame flags
const SFRAME_F_FDE_SORTED: u8 = 0x1;
#[allow(dead_code)]
const SFRAME_F_FRAME_POINTER: u8 = 0x2;

/// ABI/arch identifiers
const SFRAME_ABI_AMD64_ENDIAN_LITTLE: u8 = 3;

/// FDE types
const SFRAME_FDE_TYPE_PCINC: u8 = 0;
#[allow(dead_code)]
const SFRAME_FDE_TYPE_PCMASK: u8 = 1;

/// FRE types (address offset sizes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SFrameFREType {
    Addr1 = 0, // 8-bit address offset
    Addr2 = 1, // 16-bit address offset
    Addr4 = 2, // 32-bit address offset
}

/// FRE offset sizes (for stack offsets)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SFrameOffsetSize {
    Offset1B = 0, // 1 byte offsets
    Offset2B = 1, // 2 byte offsets
    Offset4B = 2, // 4 byte offsets
}

/// Error type for SFrame binary serialization
#[derive(Debug)]
pub enum SFrameError {
    /// PC offset doesn't fit in chosen FRE type
    PcOffsetOutOfRange {
        offset: u32,
        fre_type: SFrameFREType,
    },
    /// Stack offset doesn't fit in chosen offset size
    StackOffsetOutOfRange {
        offset: i32,
        offset_size: SFrameOffsetSize,
    },
    /// No functions with FREs to serialize
    NoFunctions,
    /// I/O error
    Io(io::Error),
}

impl From<io::Error> for SFrameError {
    fn from(e: io::Error) -> Self {
        SFrameError::Io(e)
    }
}

impl std::fmt::Display for SFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SFrameError::PcOffsetOutOfRange { offset, fre_type } => {
                write!(
                    f,
                    "PC offset 0x{:x} out of range for FRE type {:?}",
                    offset, fre_type
                )
            }
            SFrameError::StackOffsetOutOfRange {
                offset,
                offset_size,
            } => {
                write!(
                    f,
                    "Stack offset {} out of range for offset size {:?}",
                    offset, offset_size
                )
            }
            SFrameError::NoFunctions => write!(f, "No functions with FREs to serialize"),
            SFrameError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for SFrameError {}

/// Determine the optimal FRE type based on maximum PC offset
pub fn determine_fre_type(max_pc_offset: u32) -> SFrameFREType {
    if max_pc_offset <= u8::MAX as u32 {
        SFrameFREType::Addr1
    } else if max_pc_offset <= u16::MAX as u32 {
        SFrameFREType::Addr2
    } else {
        SFrameFREType::Addr4
    }
}

/// Determine the optimal offset size based on maximum absolute stack offset
pub fn determine_offset_size(max_abs_offset: i32) -> SFrameOffsetSize {
    let abs = max_abs_offset.unsigned_abs();
    if abs <= i8::MAX as u32 && max_abs_offset >= i8::MIN as i32 {
        SFrameOffsetSize::Offset1B
    } else if abs <= i16::MAX as u32 && max_abs_offset >= i16::MIN as i32 {
        SFrameOffsetSize::Offset2B
    } else {
        SFrameOffsetSize::Offset4B
    }
}

/// SFrame preamble (4 bytes)
#[repr(C, packed)]
struct SFramePreamble {
    magic: u16,
    version: u8,
    flags: u8,
}

/// SFrame header (28 bytes total including preamble)
#[repr(C, packed)]
struct SFrameHeader {
    preamble: SFramePreamble,
    abi_arch: u8,
    cfa_fixed_fp_offset: i8,
    cfa_fixed_ra_offset: i8,
    auxhdr_len: u8,
    num_fdes: u32,
    num_fres: u32,
    fre_len: u32,
    fdeoff: u32,
    freoff: u32,
}

/// SFrame Function Descriptor Entry (20 bytes)
#[repr(C, packed)]
struct SFrameFDE {
    func_start_address: i32,
    func_size: u32,
    func_start_fre_off: u32,
    func_num_fres: u32,
    func_info: u8,
    func_rep_size: u8,
    func_padding2: u16,
}

/// Encode FDE info word
fn encode_fde_info(fde_type: u8, fre_type: SFrameFREType) -> u8 {
    let fde_type_bit = (fde_type & 0x1) << 4;
    let fre_type_bits = (fre_type as u8) & 0xF;
    fde_type_bit | fre_type_bits
}

/// Encode FRE info word
fn encode_fre_info(
    cfa_base_reg: CfaBaseReg,
    offset_count: u8,
    offset_size: SFrameOffsetSize,
    mangled_ra: bool,
) -> u8 {
    let mangled_ra_bit = if mangled_ra { 1 << 7 } else { 0 };
    let offset_size_bits = ((offset_size as u8) & 0x3) << 5;
    let offset_count_bits = (offset_count & 0xF) << 1;
    let cfa_base_reg_bit = match cfa_base_reg {
        CfaBaseReg::Rsp => 0,
        CfaBaseReg::Rbp => 1,
    };

    mangled_ra_bit | offset_size_bits | offset_count_bits | cfa_base_reg_bit
}

/// Write a value in little-endian format
fn write_le<W: Write, T: ToLeBytes>(writer: &mut W, value: T) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

trait ToLeBytes {
    fn to_le_bytes(&self) -> Vec<u8>;
}

impl ToLeBytes for u8 {
    fn to_le_bytes(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl ToLeBytes for i8 {
    fn to_le_bytes(&self) -> Vec<u8> {
        vec![*self as u8]
    }
}

impl ToLeBytes for u16 {
    fn to_le_bytes(&self) -> Vec<u8> {
        u16::to_le_bytes(*self).to_vec()
    }
}

impl ToLeBytes for i16 {
    fn to_le_bytes(&self) -> Vec<u8> {
        i16::to_le_bytes(*self).to_vec()
    }
}

impl ToLeBytes for u32 {
    fn to_le_bytes(&self) -> Vec<u8> {
        u32::to_le_bytes(*self).to_vec()
    }
}

impl ToLeBytes for i32 {
    fn to_le_bytes(&self) -> Vec<u8> {
        i32::to_le_bytes(*self).to_vec()
    }
}

/// Serialize SFrame section to binary format
/// Returns a tuple of (skipped_empty_functions, merged_fres)
pub fn serialize_sframe<W: Write>(
    writer: &mut W,
    functions: &mut [FunctionDescriptor],
) -> Result<(usize, usize), SFrameError> {
    // First, deduplicate consecutive identical FREs in each function
    let mut total_merged = 0;
    for func in functions.iter_mut() {
        total_merged += func.deduplicate_fres();
    }

    // Filter out functions with no FREs (they cannot be serialized)
    let valid_functions: Vec<_> = functions.iter().filter(|f| !f.fres.is_empty()).collect();

    let skipped_count = functions.len() - valid_functions.len();

    if valid_functions.is_empty() {
        return Err(SFrameError::NoFunctions);
    }

    // Calculate what we need for the header
    let num_fdes = valid_functions.len() as u32;
    let mut num_fres = 0u32;

    // Count FREs
    for func in &valid_functions {
        num_fres += func.fres.len() as u32;
    }

    // Determine FRE types and offset sizes for each function
    let mut fre_metadata: Vec<(SFrameFREType, SFrameOffsetSize)> = Vec::new();
    for func in &valid_functions {
        let max_pc_offset = func.fres.iter().map(|fre| fre.pc_offset).max().unwrap();
        let fre_type = determine_fre_type(max_pc_offset);

        // Find max absolute stack offset across all FREs
        let max_abs_offset = func
            .fres
            .iter()
            .map(|fre| {
                let cfa_abs = fre.cfa_offset.abs();
                let fp_abs = match fre.fp_tracking {
                    super::types::FpTracking::Unchanged => 0,
                    super::types::FpTracking::AtCfaOffset(off) => (off as i32).abs(),
                };
                cfa_abs.max(fp_abs)
            })
            .max()
            .unwrap();

        let offset_size = determine_offset_size(max_abs_offset);
        fre_metadata.push((fre_type, offset_size));
    }

    // Calculate FRE section size
    let mut fre_len = 0u32;
    for (i, func) in valid_functions.iter().enumerate() {
        let (fre_type, offset_size) = fre_metadata[i];
        let fre_header_size = match fre_type {
            SFrameFREType::Addr1 => 2, // 1 byte addr + 1 byte info
            SFrameFREType::Addr2 => 3, // 2 bytes addr + 1 byte info
            SFrameFREType::Addr4 => 5, // 4 bytes addr + 1 byte info
        };
        let offset_byte_size = match offset_size {
            SFrameOffsetSize::Offset1B => 1,
            SFrameOffsetSize::Offset2B => 2,
            SFrameOffsetSize::Offset4B => 4,
        };

        for fre in &func.fres {
            // Each FRE has: address + info + offsets
            // Offsets: CFA (always), FP (if tracked)
            let num_offsets = match fre.fp_tracking {
                super::types::FpTracking::Unchanged => 1,      // CFA
                super::types::FpTracking::AtCfaOffset(_) => 2, // CFA + FP
            };
            fre_len += fre_header_size + (num_offsets * offset_byte_size);
        }
    }

    // Header offsets
    let fdeoff = 0u32; // FDE section starts right after header
    let freoff = fdeoff + (num_fdes * 20); // Each FDE is 20 bytes

    // Write header
    let header = SFrameHeader {
        preamble: SFramePreamble {
            magic: SFRAME_MAGIC,
            version: SFRAME_VERSION,
            flags: SFRAME_F_FDE_SORTED, // We'll ensure FDEs are sorted
        },
        abi_arch: SFRAME_ABI_AMD64_ENDIAN_LITTLE,
        cfa_fixed_fp_offset: 0,  // Not used for x86_64
        cfa_fixed_ra_offset: -8, // RA is always at CFA-8 on x86_64
        auxhdr_len: 0,           // No auxiliary header
        num_fdes,
        num_fres,
        fre_len,
        fdeoff,
        freoff,
    };

    // Write header fields
    write_le(writer, header.preamble.magic)?;
    write_le(writer, header.preamble.version)?;
    write_le(writer, header.preamble.flags)?;
    write_le(writer, header.abi_arch)?;
    write_le(writer, header.cfa_fixed_fp_offset)?;
    write_le(writer, header.cfa_fixed_ra_offset)?;
    write_le(writer, header.auxhdr_len)?;
    write_le(writer, header.num_fdes)?;
    write_le(writer, header.num_fres)?;
    write_le(writer, header.fre_len)?;
    write_le(writer, header.fdeoff)?;
    write_le(writer, header.freoff)?;

    // Write FDEs
    let mut current_fre_offset = 0u32;
    for (i, func) in valid_functions.iter().enumerate() {
        let (fre_type, _) = fre_metadata[i];

        let fde = SFrameFDE {
            func_start_address: func.start_addr as i32,
            func_size: func.size as u32,
            func_start_fre_off: current_fre_offset,
            func_num_fres: func.fres.len() as u32,
            func_info: encode_fde_info(SFRAME_FDE_TYPE_PCINC, fre_type),
            func_rep_size: 0, // Only used for PCMASK type
            func_padding2: 0,
        };

        write_le(writer, fde.func_start_address)?;
        write_le(writer, fde.func_size)?;
        write_le(writer, fde.func_start_fre_off)?;
        write_le(writer, fde.func_num_fres)?;
        write_le(writer, fde.func_info)?;
        write_le(writer, fde.func_rep_size)?;
        write_le(writer, fde.func_padding2)?;

        // Update FRE offset for next function
        let (fre_type, offset_size) = fre_metadata[i];
        let fre_header_size = match fre_type {
            SFrameFREType::Addr1 => 2,
            SFrameFREType::Addr2 => 3,
            SFrameFREType::Addr4 => 5,
        };
        let offset_byte_size = match offset_size {
            SFrameOffsetSize::Offset1B => 1,
            SFrameOffsetSize::Offset2B => 2,
            SFrameOffsetSize::Offset4B => 4,
        };

        for fre in &func.fres {
            let num_offsets = match fre.fp_tracking {
                super::types::FpTracking::Unchanged => 1,
                super::types::FpTracking::AtCfaOffset(_) => 2,
            };
            current_fre_offset += fre_header_size + (num_offsets * offset_byte_size);
        }
    }

    // Write FREs
    for (i, func) in valid_functions.iter().enumerate() {
        let (fre_type, offset_size) = fre_metadata[i];

        for fre in &func.fres {
            // Validate PC offset fits
            match fre_type {
                SFrameFREType::Addr1 => {
                    if fre.pc_offset > u8::MAX as u32 {
                        return Err(SFrameError::PcOffsetOutOfRange {
                            offset: fre.pc_offset,
                            fre_type,
                        });
                    }
                    write_le(writer, fre.pc_offset as u8)?;
                }
                SFrameFREType::Addr2 => {
                    if fre.pc_offset > u16::MAX as u32 {
                        return Err(SFrameError::PcOffsetOutOfRange {
                            offset: fre.pc_offset,
                            fre_type,
                        });
                    }
                    write_le(writer, fre.pc_offset as u16)?;
                }
                SFrameFREType::Addr4 => {
                    write_le(writer, fre.pc_offset)?;
                }
            }

            // Write FRE info word
            let offset_count = match fre.fp_tracking {
                super::types::FpTracking::Unchanged => 1,
                super::types::FpTracking::AtCfaOffset(_) => 2,
            };
            let info = encode_fre_info(fre.cfa_base, offset_count, offset_size, false);
            write_le(writer, info)?;

            // Write stack offsets
            // 1. CFA offset
            write_offset(writer, fre.cfa_offset, offset_size)?;

            // 2. FP offset (if tracked)
            if let super::types::FpTracking::AtCfaOffset(fp_offset) = fre.fp_tracking {
                write_offset(writer, fp_offset as i32, offset_size)?;
            }
        }
    }

    Ok((skipped_count, total_merged))
}

/// Write a stack offset in the appropriate size
fn write_offset<W: Write>(
    writer: &mut W,
    offset: i32,
    size: SFrameOffsetSize,
) -> Result<(), SFrameError> {
    match size {
        SFrameOffsetSize::Offset1B => {
            if offset < i8::MIN as i32 || offset > i8::MAX as i32 {
                return Err(SFrameError::StackOffsetOutOfRange {
                    offset,
                    offset_size: size,
                });
            }
            write_le(writer, offset as i8)?;
        }
        SFrameOffsetSize::Offset2B => {
            if offset < i16::MIN as i32 || offset > i16::MAX as i32 {
                return Err(SFrameError::StackOffsetOutOfRange {
                    offset,
                    offset_size: size,
                });
            }
            write_le(writer, offset as i16)?;
        }
        SFrameOffsetSize::Offset4B => {
            write_le(writer, offset)?;
        }
    }
    Ok(())
}
