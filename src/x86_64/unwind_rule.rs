use super::unwindregs::UnwindRegsX86_64;
use crate::add_signed::checked_add_signed;
use crate::error::Error;
use crate::unwind_rule::UnwindRule;

/// For all of these: return address is *(new_sp - 8)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnwindRuleX86_64 {
    /// (sp, bp) = (sp + 8, bp)
    JustReturn,
    /// (sp, bp) = if is_first_frame (sp + 8, bp) else (bp + 16, *bp)
    JustReturnIfFirstFrameOtherwiseFp,
    /// (sp, bp) = (sp + 8x, bp)
    OffsetSp { sp_offset_by_8: u16 },
    /// (sp, bp) = (sp + 8x, *(sp + 8y))
    OffsetSpAndRestoreBp {
        sp_offset_by_8: u16,
        bp_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, bp) = (bp + 16, *bp)
    UseFramePointer,
}

impl UnwindRule for UnwindRuleX86_64 {
    type UnwindRegs = UnwindRegsX86_64;

    fn rule_for_stub_functions() -> Self {
        UnwindRuleX86_64::JustReturn
    }
    fn rule_for_function_start() -> Self {
        UnwindRuleX86_64::JustReturn
    }
    fn fallback_rule() -> Self {
        UnwindRuleX86_64::UseFramePointer
    }

    fn exec<F>(
        self,
        is_first_frame: bool,
        regs: &mut UnwindRegsX86_64,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let checked_add = |lhs: u64, rhs: u64| lhs.checked_add(rhs).ok_or(Error::IntegerOverflow);
        let checked_add_signed = |lhs:u64, rhs: i64| checked_add_signed(lhs, rhs).ok_or(Error::IntegerOverflow);
        let mut read_stack = |addr: u64| read_stack(addr).map_err(|_| Error::CouldNotReadStack(addr));

        let sp = regs.sp();
        let (new_sp, new_bp) = match self {
            UnwindRuleX86_64::JustReturn => {
                let new_sp = checked_add(sp, 8)?;
                (new_sp, regs.bp())
            }
            UnwindRuleX86_64::JustReturnIfFirstFrameOtherwiseFp => {
                if is_first_frame {
                    let new_sp = checked_add(sp, 8)?;
                    (new_sp, regs.bp())
                } else {
                    let sp = regs.sp();
                    let bp = regs.bp();
                    let new_sp = checked_add(bp, 16)?;
                    if new_sp <= sp {
                        return Err(Error::FramepointerUnwindingMovedBackwards);
                    }
                    let new_bp = read_stack(bp).map_err(|_| Error::CouldNotReadStack(bp))?;
                    (new_sp, new_bp)
                }
            }
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8 } => {
                let sp_offset = u64::from(sp_offset_by_8) * 8;
                let new_sp = checked_add(sp, sp_offset)?;
                (new_sp, regs.bp())
            }
            UnwindRuleX86_64::OffsetSpAndRestoreBp {
                sp_offset_by_8,
                bp_storage_offset_from_sp_by_8,
            } => {
                let sp_offset = u64::from(sp_offset_by_8) * 8;
                let new_sp = checked_add(sp, sp_offset)?;
                let bp_storage_offset_from_sp = i64::from(bp_storage_offset_from_sp_by_8) * 8;
                let bp_location = checked_add_signed(sp, bp_storage_offset_from_sp)?;
                let new_bp = match read_stack(bp_location) {
                    Ok(new_bp) => new_bp,
                    Err(_) if is_first_frame && bp_location < sp => {
                        // Ignore errors when reading beyond the stack pointer in the first frame.
                        // These negative offsets are sometimes seen in x86_64 epilogues, where
                        // a bunch of registers are popped one after the other, and the compiler
                        // doesn't always set the already-popped register to "unchanged" (because
                        // doing so would take up extra space in the dwarf information).
                        // read_stack may legitimately refuse to read beyond the stack pointer,
                        // for example when the stack bytes are coming from a linux perf event
                        // sample record, where the ustack bytes are copied starting from sp.
                        regs.bp()
                    }
                    Err(e) => return Err(e),
                };
                (new_sp, new_bp)
            }
            UnwindRuleX86_64::UseFramePointer => {
                // Do a frame pointer stack walk. Code that is compiled with frame pointers
                // has the following function prologues and epilogues:
                //
                // Function prologue:
                // pushq  %rbp
                // movq   %rsp, %rbp
                //
                // Function epilogue:
                // popq   %rbp
                // ret
                //
                // Functions are called with callq; callq pushes the return address onto the stack.
                // When a function reaches its end, ret pops the return address from the stack and jumps to it.
                // So when a function is called, we have the following stack layout:
                //
                //                                                                     [... rest of the stack]
                //                                                                     ^ rsp           ^ rbp
                //     callq some_function
                //                                                   [return address]  [... rest of the stack]
                //                                                   ^ rsp                             ^ rbp
                //     pushq %rbp
                //                         [caller's frame pointer]  [return address]  [... rest of the stack]
                //                         ^ rsp                                                       ^ rbp
                //     movq %rsp, %rbp
                //                         [caller's frame pointer]  [return address]  [... rest of the stack]
                //                         ^ rsp, rbp
                //     <other instructions>
                //       [... more stack]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //       ^ rsp             ^ rbp
                //
                // So: *rbp is the caller's frame pointer, and *(rbp + 8) is the return address.
                //
                // Or, in other words, the following linked list is built up on the stack:
                // #[repr(C)]
                // struct CallFrameInfo {
                //     previous: *const CallFrameInfo,
                //     return_address: *const c_void,
                // }
                // and rbp is a *const CallFrameInfo.
                let sp = regs.sp();
                let bp = regs.bp();
                if bp == 0 {
                    return Ok(None);
                }
                let new_sp = checked_add(bp, 16)?;
                if new_sp <= sp {
                    return Err(Error::FramepointerUnwindingMovedBackwards);
                }
                let new_bp = read_stack(bp).map_err(|_| Error::CouldNotReadStack(bp))?;
                // new_bp is the caller's bp. If the caller uses frame pointers, then bp should be
                // a valid frame pointer and we could do a coherency check on new_bp to make sure
                // it's moving in the right direction. But if the caller is using bp as a general
                // purpose register, then any value (including zero) would be a valid value.
                // At this point we don't know how the caller uses bp, so we leave new_bp unchecked.

                (new_sp, new_bp)
            }
        };
        let return_address =
            read_stack(new_sp - 8).map_err(|_| Error::CouldNotReadStack(new_sp - 8))?;
        if return_address == 0 {
            return Ok(None);
        }
        if new_sp == sp && return_address == regs.ip() {
            return Err(Error::DidNotAdvance);
        }
        regs.set_ip(return_address);
        regs.set_sp(new_sp);
        regs.set_bp(new_bp);
        Ok(Some(return_address))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic() {
        let stack = [
            1, 2, 0x100300, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsX86_64::new(0x100400, 0x10, 0x20);
        let res =
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8: 1 }.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100300)));
        assert_eq!(regs.ip(), 0x100300);
        assert_eq!(regs.sp(), 0x18);
        assert_eq!(regs.bp(), 0x20);
        let res = UnwindRuleX86_64::UseFramePointer.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100200)));
        assert_eq!(regs.ip(), 0x100200);
        assert_eq!(regs.sp(), 0x30);
        assert_eq!(regs.bp(), 0x40);
        let res = UnwindRuleX86_64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100100)));
        assert_eq!(regs.ip(), 0x100100);
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.bp(), 0x70);
        let res = UnwindRuleX86_64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(None));
    }

    #[test]
    fn test_overflow() {
        // This test makes sure that debug builds don't panic when trying to use frame pointer
        // unwinding on code that was using the bp register as a general-purpose register and
        // storing -1 in it. -1 is u64::MAX, so an unchecked add panics in debug builds.
        let stack = [
            1, 2, 0x100300, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsX86_64::new(0x100400, u64::MAX / 8 * 8, u64::MAX);
        let res = UnwindRuleX86_64::JustReturn.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Err(Error::IntegerOverflow));
        let res =
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8: 1 }.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Err(Error::IntegerOverflow));
        let res = UnwindRuleX86_64::OffsetSpAndRestoreBp {
            sp_offset_by_8: 1,
            bp_storage_offset_from_sp_by_8: 2,
        }
        .exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Err(Error::IntegerOverflow));
        let res = UnwindRuleX86_64::UseFramePointer.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Err(Error::IntegerOverflow));
    }
}
