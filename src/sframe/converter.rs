use super::types::{CfaBaseReg, FpTracking, FrameRowEntry};
/// Conversion logic from framehop UnwindRuleX86_64 to SFrame FRE
use crate::x86_64::{Reg, UnwindRuleX86_64};

/// Result of converting an unwind rule to SFrame
#[derive(Debug)]
pub enum ConversionResult {
    /// Successfully converted to a single FRE
    Single(FrameRowEntry),
    /// Rule cannot be represented in SFrame (with reason)
    Unsupported(&'static str),
    /// Special case that should be skipped
    Skip(&'static str),
}

/// Convert a framehop UnwindRuleX86_64 to an SFrame FrameRowEntry
///
/// # Arguments
/// * `rule` - The framehop unwind rule to convert
/// * `pc_offset` - The PC offset from function start where this rule applies
///
/// # Returns
/// A ConversionResult indicating success or the reason for failure
pub fn convert_unwind_rule(rule: UnwindRuleX86_64, pc_offset: u32) -> ConversionResult {
    match rule {
        // (sp, bp) = (sp + 8, bp)
        // After: CFA = new_sp = old_sp + 8
        // So: CFA = RSP + 8, FP unchanged
        UnwindRuleX86_64::JustReturn => ConversionResult::Single(FrameRowEntry::new(
            pc_offset,
            CfaBaseReg::Rsp,
            8,
            FpTracking::Unchanged,
        )),

        // (sp, bp) = (sp + 8x, bp)
        // After: CFA = new_sp = old_sp + 8*sp_offset_by_8
        // So: CFA = RSP + (8*sp_offset_by_8), FP unchanged
        UnwindRuleX86_64::OffsetSp { sp_offset_by_8 } => {
            let cfa_offset = (sp_offset_by_8 as i32) * 8;
            ConversionResult::Single(FrameRowEntry::new(
                pc_offset,
                CfaBaseReg::Rsp,
                cfa_offset,
                FpTracking::Unchanged,
            ))
        }

        // (sp, bp) = (sp + 8*sp_off, *(sp + 8*bp_off))
        // After: CFA = new_sp = old_sp + 8*sp_offset_by_8
        // BP is loaded from: old_sp + 8*bp_storage_offset_from_sp_by_8
        // Express BP location relative to CFA:
        //   bp_addr = old_sp + 8*bp_storage_offset_from_sp_by_8
        //   bp_addr = (CFA - 8*sp_offset_by_8) + 8*bp_storage_offset_from_sp_by_8
        //   bp_addr = CFA + 8*(bp_storage_offset_from_sp_by_8 - sp_offset_by_8)
        UnwindRuleX86_64::OffsetSpAndRestoreBp {
            sp_offset_by_8,
            bp_storage_offset_from_sp_by_8,
        } => {
            let cfa_offset = (sp_offset_by_8 as i32) * 8;
            let fp_offset_from_cfa =
                ((bp_storage_offset_from_sp_by_8 as i32) - (sp_offset_by_8 as i32)) * 8;

            ConversionResult::Single(FrameRowEntry::new(
                pc_offset,
                CfaBaseReg::Rsp,
                cfa_offset,
                FpTracking::AtCfaOffset(fp_offset_from_cfa as i16),
            ))
        }

        // (sp, bp) = (bp + 16, *bp)
        // After: CFA = new_sp = old_bp + 16
        // So: CFA = RBP + 16
        // BP is loaded from: old_bp = CFA - 16
        UnwindRuleX86_64::UseFramePointer => ConversionResult::Single(FrameRowEntry::new(
            pc_offset,
            CfaBaseReg::Rbp,
            16,
            FpTracking::AtCfaOffset(-16),
        )),

        // This rule pops multiple callee-saved registers from the stack.
        // SFrame primarily tracks CFA, FP, and RA. We can track the SP adjustment
        // and FP restoration if RBP is in the register list, but we can't fully
        // represent the restoration of all registers.
        UnwindRuleX86_64::OffsetSpAndPopRegisters {
            sp_offset_by_8,
            register_count,
            encoded_registers_to_pop,
        } => {
            // Calculate total SP adjustment: initial offset + space for popped registers + return address
            let total_sp_adjustment = (sp_offset_by_8 as i32) * 8 + (register_count as i32) * 8 + 8;

            // Check if RBP is in the registers to pop
            use crate::x86_64::register_ordering;
            let regs = register_ordering::decode(register_count, encoded_registers_to_pop);
            let rbp_index = regs.iter().position(|r| matches!(r, Reg::RBP));

            let fp_tracking = if let Some(idx) = rbp_index {
                // RBP is restored from stack at position (sp_offset + idx*8)
                // Relative to CFA: CFA - total_sp_adjustment + sp_offset + idx*8
                let rbp_offset_from_sp = (sp_offset_by_8 as i32) * 8 + (idx as i32) * 8;
                let rbp_offset_from_cfa = rbp_offset_from_sp - total_sp_adjustment;
                FpTracking::AtCfaOffset(rbp_offset_from_cfa as i16)
            } else {
                FpTracking::Unchanged
            };

            eprintln!(
                "Warning: OffsetSpAndPopRegisters at +0x{:x} pops {} registers. \
                 SFrame cannot represent full register restoration. \
                 Only tracking CFA and FP.",
                pc_offset, register_count
            );

            ConversionResult::Single(FrameRowEntry::new(
                pc_offset,
                CfaBaseReg::Rsp,
                total_sp_adjustment,
                fp_tracking,
            ))
        }

        // Conditional rule: behaves differently for first frame vs others
        // For SFrame, we use the more conservative UseFramePointer variant
        UnwindRuleX86_64::JustReturnIfFirstFrameOtherwiseFp => {
            eprintln!(
                "Warning: JustReturnIfFirstFrameOtherwiseFp at +0x{:x} has conditional behavior. \
                 Using UseFramePointer variant for SFrame.",
                pc_offset
            );
            ConversionResult::Single(FrameRowEntry::new(
                pc_offset,
                CfaBaseReg::Rbp,
                16,
                FpTracking::AtCfaOffset(-16),
            ))
        }

        // End of stack marker - this shouldn't generate an FRE
        UnwindRuleX86_64::EndOfStack => ConversionResult::Skip("EndOfStack marker"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_just_return() {
        let result = convert_unwind_rule(UnwindRuleX86_64::JustReturn, 0);
        if let ConversionResult::Single(fre) = result {
            assert_eq!(fre.cfa_base, CfaBaseReg::Rsp);
            assert_eq!(fre.cfa_offset, 8);
            assert_eq!(fre.fp_tracking, FpTracking::Unchanged);
        } else {
            panic!("Expected Single result");
        }
    }

    #[test]
    fn test_offset_sp() {
        let result = convert_unwind_rule(UnwindRuleX86_64::OffsetSp { sp_offset_by_8: 4 }, 0);
        if let ConversionResult::Single(fre) = result {
            assert_eq!(fre.cfa_base, CfaBaseReg::Rsp);
            assert_eq!(fre.cfa_offset, 32);
            assert_eq!(fre.fp_tracking, FpTracking::Unchanged);
        } else {
            panic!("Expected Single result");
        }
    }

    #[test]
    fn test_use_frame_pointer() {
        let result = convert_unwind_rule(UnwindRuleX86_64::UseFramePointer, 0);
        if let ConversionResult::Single(fre) = result {
            assert_eq!(fre.cfa_base, CfaBaseReg::Rbp);
            assert_eq!(fre.cfa_offset, 16);
            assert_eq!(fre.fp_tracking, FpTracking::AtCfaOffset(-16));
        } else {
            panic!("Expected Single result");
        }
    }
}
