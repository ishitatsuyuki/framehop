use std::marker::PhantomData;

use crate::arch::Arch;
use crate::unwind_result::UnwindResult;
use crate::ModuleSvmaInfo;

pub trait RvaMapper {
    fn map(&self, rva: u32) -> Option<&[u8]>;
}

impl<'a> RvaMapper for &'a (dyn RvaMapper + 'a) {
    fn map(&self, rva: u32) -> Option<&[u8]> {
        (*self).map(rva)
    }
}

pub struct SehUnwinder<'a, F: RvaMapper, A: SehUnwinding> {
    exception_data: &'a [u8],
    base_avma: u64,
    rva_mapper: F,
    _arch: PhantomData<A>,
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SehUnwinderError {
    #[error("Invalid RUNTIME_FUNCTION section")]
    InvalidRuntimeFunction,
    #[error("Could not find SEH unwind info for the requested address")]
    UnwindInfoForAddressFailed,
    #[error("Could not map unwind info RVA to file offset")]
    UnwindRvaMappingFailed,
}

impl<'a, F: RvaMapper, A: SehUnwinding> SehUnwinder<'a, F, A> {
    pub fn new(exception_data: &'a [u8], rva_mapper: F, base_avma: u64) -> Self {
        Self {
            exception_data,
            rva_mapper,
            base_avma,
            _arch: PhantomData,
        }
    }

    pub fn unwind_frame(
        &mut self,
        regs: &mut A::UnwindRegs,
        is_first_frame: bool,
        mut read_stack: impl FnMut(u64) -> Result<u64, ()>,
    ) -> Result<UnwindResult<A::UnwindRule>, SehUnwinderError> {
        let result = A::unwind_frame(
            self.exception_data,
            &mut self.rva_mapper,
            self.base_avma,
            regs,
            is_first_frame,
            &mut read_stack,
        );
        if let Err(SehUnwinderError::UnwindInfoForAddressFailed) = result {
            Ok(UnwindResult::ExecRule(A::rule_if_uncovered_by_seh()))
        } else {
            result
        }
    }
}

pub trait SehUnwinding: Arch {
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
        G: FnMut(u64) -> Result<u64, ()>;

    fn rule_if_uncovered_by_seh() -> Self::UnwindRule;
}
