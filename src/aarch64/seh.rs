use crate::aarch64::ArchAarch64;
use crate::seh::{RvaMapper, SehUnwinderError, SehUnwinding};
use crate::unwind_result::UnwindResult;

impl SehUnwinding for ArchAarch64 {
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
        todo!()
    }

    fn rule_if_uncovered_by_seh() -> Self::UnwindRule {
        todo!()
    }
}
