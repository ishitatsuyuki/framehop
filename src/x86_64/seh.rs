use crate::seh::{RvaMapper, SehUnwinderError, SehUnwinding};
use crate::unwind_result::UnwindResult;
use crate::x86_64::{ArchX86_64, UnwindRegsX86_64, UnwindRuleX86_64};
use crate::ModuleSvmaInfo;
use goblin::pe::exception::{
    ExceptionData, Register, StackFrameOffset, UnwindInfo, UnwindOperation,
};
use std::iter;
use zerocopy::{FromBytes, LayoutVerified};

const REG_SIZE: i32 = 8;
const RBP: Register = Register(5);

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Default, FromBytes)]
pub struct RuntimeFunction {
    /// Function start address.
    pub begin_address: u32,
    /// Function end address.
    pub end_address: u32,
    /// Unwind info address.
    pub unwind_info_address: u32,
}

struct UnwindInfoChunk<I: IntoIterator<Item = UnwindOperation>> {
    codes: I,
    frame_register: Register,
    frame_register_offset: u32,
}

fn seh_to_unwind_rule<
    I: IntoIterator<Item = UnwindInfoChunk<J>>,
    J: IntoIterator<Item = UnwindOperation>,
>(
    chunks: I,
) -> Result<UnwindRuleX86_64, goblin::error::Error> {
    let mut use_bp = false;
    // (new_sp - sp) if !use_bp, (new_sp - bp) if use_bp.
    let mut sp_offset = 0;
    // &new_bp - sp if !use_bp, &new_bp - bp if use_bp.
    let mut bp_offset = None;

    for chunk in chunks {
        if chunk.frame_register != RBP {
            // TODO: error out
        }
        for op in chunk.codes {
            match op {
                UnwindOperation::PushNonVolatile(reg) => {
                    if reg == RBP {
                        bp_offset = Some(sp_offset);
                    }
                    sp_offset += REG_SIZE;
                }
                UnwindOperation::Alloc(size) => {
                    sp_offset += size as i32;
                }
                UnwindOperation::SetFPRegister => {
                    sp_offset = -(chunk.frame_register_offset as i32);
                    use_bp = true;
                }
                UnwindOperation::SaveNonVolatile(reg, offset) => {
                    if reg == RBP {
                        if let StackFrameOffset::RSP(offset) = offset {
                            bp_offset = Some(offset as i32);
                        } else {
                            // TODO: error out
                        }
                    }
                }
                UnwindOperation::SaveXMM(_, _) => {}
                UnwindOperation::SaveXMM128(_, _) => {}
                UnwindOperation::PushMachineFrame(_) => {
                    // TODO
                }
                UnwindOperation::Epilog => {}
                UnwindOperation::Noop => {}
            }
        }
    }

    // Final adjustment for return address.
    sp_offset += REG_SIZE;

    Ok(if use_bp {
        UnwindRuleX86_64::UseBasePointer {
            sp_offset_from_bp_by_8: (sp_offset / 8) as u16, // TODO: overflow
            bp_storage_offset_from_bp_by_8: (bp_offset.unwrap() / 8) as i16, // TODO: overflow
        }
    } else {
        match bp_offset {
            Some(bp_offset) => UnwindRuleX86_64::OffsetSpAndRestoreBp {
                sp_offset_by_8: (sp_offset / 8) as u16, // TODO: overflow
                bp_storage_offset_from_sp_by_8: (bp_offset / 8) as i16, // TODO: overflow
            },
            None => UnwindRuleX86_64::OffsetSp {
                sp_offset_by_8: (sp_offset / 8) as u16, // TODO: overflow
            },
        }
    })
}

impl SehUnwinding for ArchX86_64 {
    fn unwind_frame<'a, F, G>(
        exception_data: &'a [u8],
        rva_mapper: &mut F,
        base_avma: u64,
        regs: &mut Self::UnwindRegs,
        is_first_frame: bool,
        read_stack: &mut G,
    ) -> Result<UnwindResult<Self::UnwindRule>, SehUnwinderError>
    where
        F: RvaMapper,
        G: FnMut(u64) -> Result<u64, ()>,
    {
        let runtime_function: &[RuntimeFunction] = LayoutVerified::new_slice(exception_data)
            .ok_or(SehUnwinderError::InvalidRuntimeFunction)?
            .into_slice();
        let ip = (regs.ip() - base_avma) as u32; // TODO: overflow
        let idx = runtime_function
            .partition_point(|f| f.begin_address <= ip)
            .saturating_sub(1);
        let func = &runtime_function[idx];
        if func.end_address <= ip {
            return Err(SehUnwinderError::UnwindInfoForAddressFailed);
        }
        let func_offset = ip - func.begin_address;

        let unwind_info = rva_mapper
            .map(func.unwind_info_address)
            .ok_or(SehUnwinderError::UnwindRvaMappingFailed)?;
        let unwind_info = UnwindInfo::parse(unwind_info, 0).unwrap();
        let unwind_chain = iter::successors(Some(unwind_info), |info| {
            info.chained_info.map(|f| {
                let unwind_info = rva_mapper.map(f.unwind_info_address);
                UnwindInfo::parse(unwind_info.unwrap(), 0).unwrap()
            })
        });

        // eprintln!("base_avma: {:#x}, ip: {:#x}", base_avma, ip);
        Ok(UnwindResult::ExecRule(
            seh_to_unwind_rule(unwind_chain.enumerate().map(|(i, info)| {
                let is_first = i == 0;
                UnwindInfoChunk {
                    codes: info
                        .unwind_codes()
                        .skip_while(move |x| {
                            is_first && x.as_ref().unwrap().code_offset as u32 > func_offset
                        })
                        .map(|x| x.unwrap().operation),
                    frame_register: info.frame_register,
                    frame_register_offset: info.frame_register_offset,
                }
            }))
            .unwrap(),
        ))
    }

    fn rule_if_uncovered_by_seh() -> Self::UnwindRule {
        UnwindRuleX86_64::JustReturn
    }
}

#[cfg(test)]
mod tests {
    use crate::x86_64::seh::UnwindInfoChunk;
    use goblin::pe::exception::{Register, StackFrameOffset, UnwindOperation};

    #[test]
    fn with_sp() {
        let codes = [
            // 0x3B: SAVE_NONVOL reg=R13, offset=0x50
            // 0x36: SAVE_NONVOL reg=R12, offset=0x48
            // 0x31: SAVE_NONVOL reg=RDI, offset=0x40
            // 0x08: ALLOC_SMALL size=32
            // 0x04: PUSH_NONVOL reg=RSI
            // 0x03: PUSH_NONVOL reg=RBP
            // 0x02: PUSH_NONVOL reg=RBX
            UnwindOperation::SaveNonVolatile(Register(13), StackFrameOffset::RSP(0x50)),
            UnwindOperation::SaveNonVolatile(Register(12), StackFrameOffset::RSP(0x48)),
            UnwindOperation::SaveNonVolatile(Register(7), StackFrameOffset::RSP(0x40)),
            UnwindOperation::Alloc(32),
            UnwindOperation::PushNonVolatile(Register(6)),
            UnwindOperation::PushNonVolatile(Register(5)),
            UnwindOperation::PushNonVolatile(Register(3)),
        ];
        let rule = super::seh_to_unwind_rule([UnwindInfoChunk {
            codes,
            frame_register: Register(0),
            frame_register_offset: 0,
        }])
        .unwrap();
        assert_eq!(
            rule,
            super::UnwindRuleX86_64::OffsetSpAndRestoreBp {
                sp_offset_by_8: 8,
                bp_storage_offset_from_sp_by_8: 5,
            }
        );
    }

    #[test]
    fn with_bp() {
        let codes = [
            // 0x16: ALLOC_LARGE size=152
            // 0x0F: PUSH_NONVOL reg=RBX
            // 0x0E: PUSH_NONVOL reg=RSI
            // 0x0D: PUSH_NONVOL reg=RDI
            // 0x0C: PUSH_NONVOL reg=R12
            // 0x0A: PUSH_NONVOL reg=R13
            // 0x08: PUSH_NONVOL reg=R14
            // 0x06: PUSH_NONVOL reg=R15
            // 0x04: SET_FPREG reg=RBP, offset=0x0
            // 0x01: PUSH_NONVOL reg=RBP
            UnwindOperation::Alloc(152),
            UnwindOperation::PushNonVolatile(Register(3)),
            UnwindOperation::PushNonVolatile(Register(6)),
            UnwindOperation::PushNonVolatile(Register(7)),
            UnwindOperation::PushNonVolatile(Register(12)),
            UnwindOperation::PushNonVolatile(Register(13)),
            UnwindOperation::PushNonVolatile(Register(14)),
            UnwindOperation::PushNonVolatile(Register(15)),
            UnwindOperation::SetFPRegister,
            UnwindOperation::PushNonVolatile(Register(5)),
        ];
        let rule = super::seh_to_unwind_rule([UnwindInfoChunk {
            codes,
            frame_register: Register(5),
            frame_register_offset: 0,
        }])
        .unwrap();
        assert_eq!(
            rule,
            super::UnwindRuleX86_64::UseBasePointer {
                sp_offset_from_bp_by_8: 2,
                bp_storage_offset_from_bp_by_8: 0,
            }
        );
    }

    #[test]
    fn midstack_bp() {
        // 0x25: SAVE_NONVOL reg=RDI, offset=0x80
        // 0x1E: SAVE_NONVOL reg=RSI, offset=0x78
        // 0x17: SAVE_NONVOL reg=RBX, offset=0x70
        // 0x13: SET_FPREG reg=RBP, offset=0x30
        // 0x0E: ALLOC_SMALL size=64
        // 0x0A: PUSH_NONVOL reg=R15
        // 0x08: PUSH_NONVOL reg=R14
        // 0x06: PUSH_NONVOL reg=R13
        // 0x04: PUSH_NONVOL reg=R12
        // 0x02: PUSH_NONVOL reg=RBP
        let codes = [
            UnwindOperation::SaveNonVolatile(Register(7), StackFrameOffset::RSP(0x80)),
            UnwindOperation::SaveNonVolatile(Register(6), StackFrameOffset::RSP(0x78)),
            UnwindOperation::SaveNonVolatile(Register(3), StackFrameOffset::RSP(0x70)),
            UnwindOperation::SetFPRegister,
            UnwindOperation::Alloc(64),
            UnwindOperation::PushNonVolatile(Register(15)),
            UnwindOperation::PushNonVolatile(Register(14)),
            UnwindOperation::PushNonVolatile(Register(13)),
            UnwindOperation::PushNonVolatile(Register(12)),
            UnwindOperation::PushNonVolatile(Register(5)),
        ];
        let rule = super::seh_to_unwind_rule([UnwindInfoChunk {
            codes,
            frame_register: Register(5),
            frame_register_offset: 0x30,
        }])
        .unwrap();
        assert_eq!(
            rule,
            super::UnwindRuleX86_64::UseBasePointer {
                sp_offset_from_bp_by_8: 8,
                bp_storage_offset_from_bp_by_8: 6,
            }
        );
    }
}
