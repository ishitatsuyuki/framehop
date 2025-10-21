/// SFrame data structures for x86_64 architecture
/// Based on the SFrame specification v2

/// CFA (Canonical Frame Address) base register for x86_64
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfaBaseReg {
    /// Stack pointer (RSP)
    Rsp,
    /// Frame pointer (RBP)
    Rbp,
}

impl CfaBaseReg {
    pub fn as_str(&self) -> &'static str {
        match self {
            CfaBaseReg::Rsp => "RSP",
            CfaBaseReg::Rbp => "RBP",
        }
    }
}

/// How the frame pointer is tracked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpTracking {
    /// Frame pointer is unchanged from previous frame
    Unchanged,
    /// Frame pointer is stored at CFA + offset
    AtCfaOffset(i16),
}

impl FpTracking {
    pub fn format(&self) -> String {
        match self {
            FpTracking::Unchanged => "unchanged".to_string(),
            FpTracking::AtCfaOffset(offset) => {
                if *offset >= 0 {
                    format!("[CFA+{}]", offset)
                } else {
                    format!("[CFA{}]", offset)
                }
            }
        }
    }
}

/// A Frame Row Entry (FRE) describes the unwind information at a specific PC
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRowEntry {
    /// PC offset from function start (in bytes)
    pub pc_offset: u32,
    /// Base register for CFA calculation
    pub cfa_base: CfaBaseReg,
    /// Offset to add to base register to get CFA
    pub cfa_offset: i32,
    /// How to track the frame pointer
    pub fp_tracking: FpTracking,
}

impl FrameRowEntry {
    pub fn new(
        pc_offset: u32,
        cfa_base: CfaBaseReg,
        cfa_offset: i32,
        fp_tracking: FpTracking,
    ) -> Self {
        Self {
            pc_offset,
            cfa_base,
            cfa_offset,
            fp_tracking,
        }
    }

    /// Format as human-readable text
    pub fn format(&self) -> String {
        format!(
            "FRE @ +0x{:x}: CFA={}+{} FP={} RA=[CFA-8]",
            self.pc_offset,
            self.cfa_base.as_str(),
            self.cfa_offset,
            self.fp_tracking.format()
        )
    }
}

/// Function Descriptor Entry (FDE) describes a function
#[derive(Debug, Clone)]
pub struct FunctionDescriptor {
    /// Function name (if available)
    pub name: Option<String>,
    /// Function start address (absolute)
    pub start_addr: u64,
    /// Function size in bytes
    pub size: u64,
    /// Frame row entries for this function
    pub fres: Vec<FrameRowEntry>,
}

impl FunctionDescriptor {
    pub fn new(name: Option<String>, start_addr: u64, size: u64) -> Self {
        Self {
            name,
            start_addr,
            size,
            fres: Vec::new(),
        }
    }

    pub fn add_fre(&mut self, fre: FrameRowEntry) {
        self.fres.push(fre);
    }

    /// Format as human-readable text
    pub fn format(&self) -> String {
        let mut output = String::new();
        let name = self.name.as_deref().unwrap_or("<unknown>");
        output.push_str(&format!(
            "Function: {} (0x{:x}-0x{:x})\n",
            name,
            self.start_addr,
            self.start_addr + self.size
        ));
        for fre in &self.fres {
            output.push_str("  ");
            output.push_str(&fre.format());
            output.push('\n');
        }
        output
    }
}
