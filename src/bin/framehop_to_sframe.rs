use clap::Parser;
use framehop::sframe::{
    convert_unwind_rule, serialize_sframe, ConversionResult, FunctionDescriptor,
};
use framehop::x86_64::UnwindRuleX86_64;
use gimli::{
    BaseAddresses, CfaRule, CieOrFde, DebugFrame, EhFrame, LittleEndian, Reader, RegisterRule,
    UnwindContext, UnwindContextStorage, UnwindSection, X86_64,
};
use object::{Object, ObjectSection};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::PathBuf;

/// Statistics for conversion process
#[derive(Debug, Default)]
struct ConversionStats {
    total_fdes: usize,
    total_rows: usize,
    successful_fres: usize,
    translation_failures: usize,
    unsupported: usize,
    skipped: usize,
    empty_functions: usize,
    merged_fres: usize,
}

#[derive(Parser)]
#[command(name = "framehop-to-sframe")]
#[command(about = "Convert framehop unwind rules to SFrame format")]
struct Args {
    /// Path to the ELF binary
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// Output file for SFrame binary (if not specified, outputs text to stdout)
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Show detailed conversion information
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Read the ELF file
    let file_data = fs::read(&args.file)?;
    let obj_file = object::File::parse(&*file_data)?;

    // Check architecture
    if obj_file.architecture() != object::Architecture::X86_64 {
        eprintln!("Warning: File is not x86_64 architecture. Results may be incorrect.");
    }

    // Try to find and process .eh_frame first, then .debug_frame
    let mut stats = ConversionStats::default();
    let functions = if let Some(eh_frame_section) = obj_file.section_by_name(".eh_frame") {
        if args.verbose {
            eprintln!("Found .eh_frame section");
        }
        let eh_frame_data = eh_frame_section.data()?;

        // Get base addresses
        let bases = get_base_addresses(&obj_file);

        process_eh_frame(eh_frame_data, bases, args.verbose, &mut stats)?
    } else if let Some(debug_frame_section) = obj_file.section_by_name(".debug_frame") {
        if args.verbose {
            eprintln!("Found .debug_frame section");
        }
        let debug_frame_data = debug_frame_section.data()?;

        // Get base addresses
        let bases = get_base_addresses(&obj_file);

        process_debug_frame(debug_frame_data, bases, args.verbose, &mut stats)?
    } else {
        eprintln!("Error: No .eh_frame or .debug_frame section found in binary");
        std::process::exit(1);
    };

    // Output results
    if let Some(output_path) = args.output {
        // Write binary SFrame format
        let file = File::create(&output_path)?;
        let mut writer = BufWriter::new(file);

        // Convert BTreeMap to Vec for serialization
        let mut func_vec: Vec<_> = functions.into_values().collect();

        let (skipped_empty, merged) = serialize_sframe(&mut writer, &mut func_vec)?;
        stats.empty_functions = skipped_empty;
        stats.merged_fres = merged;

        // Print statistics
        eprintln!("\nConversion Statistics:");
        eprintln!("  Total FDEs processed: {}", stats.total_fdes);
        eprintln!("  Total unwind rows:    {}", stats.total_rows);
        eprintln!("  Successful FREs:      {}", stats.successful_fres);
        eprintln!("  Translation failures: {}", stats.translation_failures);
        eprintln!("  Unsupported:          {}", stats.unsupported);
        eprintln!("  Skipped:              {}", stats.skipped);
        if stats.merged_fres > 0 {
            eprintln!("  Merged duplicate FREs: {}", stats.merged_fres);
        }
        if stats.empty_functions > 0 {
            eprintln!(
                "  Empty functions:      {} (excluded from output)",
                stats.empty_functions
            );
        }

        if stats.total_rows > 0 {
            let success_rate = (stats.successful_fres as f64 / stats.total_rows as f64) * 100.0;
            eprintln!("  Success rate:         {:.2}%", success_rate);
        }

        eprintln!("\nSFrame section written to {}", output_path.display());
    } else {
        // Print text format to stdout
        for (_addr, func) in functions {
            print!("{}", func.format());
        }
    }

    Ok(())
}

fn get_base_addresses(obj_file: &object::File) -> BaseAddresses {
    let mut bases = BaseAddresses::default();

    if let Some(eh_frame) = obj_file.section_by_name(".eh_frame") {
        bases = bases.set_eh_frame(eh_frame.address());
    }
    if let Some(eh_frame_hdr) = obj_file.section_by_name(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(eh_frame_hdr.address());
    }
    if let Some(text) = obj_file.section_by_name(".text") {
        bases = bases.set_text(text.address());
    }
    if let Some(got) = obj_file.section_by_name(".got") {
        bases = bases.set_got(got.address());
    }

    bases
}

fn process_eh_frame(
    eh_frame_data: &[u8],
    bases: BaseAddresses,
    verbose: bool,
    stats: &mut ConversionStats,
) -> Result<BTreeMap<u64, FunctionDescriptor>, Box<dyn std::error::Error>> {
    let mut eh_frame = EhFrame::new(eh_frame_data, LittleEndian);
    eh_frame.set_address_size(8);

    process_unwind_section(eh_frame, bases, verbose, stats)
}

fn process_debug_frame(
    debug_frame_data: &[u8],
    bases: BaseAddresses,
    verbose: bool,
    stats: &mut ConversionStats,
) -> Result<BTreeMap<u64, FunctionDescriptor>, Box<dyn std::error::Error>> {
    let mut debug_frame = DebugFrame::new(debug_frame_data, LittleEndian);
    debug_frame.set_address_size(8);

    process_unwind_section(debug_frame, bases, verbose, stats)
}

fn process_unwind_section<R, US>(
    unwind_section: US,
    bases: BaseAddresses,
    verbose: bool,
    stats: &mut ConversionStats,
) -> Result<BTreeMap<u64, FunctionDescriptor>, Box<dyn std::error::Error>>
where
    R: Reader,
    US: UnwindSection<R>,
{
    let mut entries = unwind_section.entries(&bases);

    // Store functions by start address for sorting
    let mut functions: BTreeMap<u64, FunctionDescriptor> = BTreeMap::new();

    while let Some(entry) = entries.next()? {
        match entry {
            CieOrFde::Cie(_cie) => {
                // Skip CIEs, we'll parse them as needed
            }
            CieOrFde::Fde(partial_fde) => {
                let fde = partial_fde.parse(|unwind_section, bases, cie_offset| {
                    unwind_section.cie_from_offset(bases, cie_offset)
                })?;

                let start_addr = fde.initial_address();
                let size = fde.len();

                if verbose {
                    eprintln!(
                        "Processing FDE: start=0x{:x}, size=0x{:x}",
                        start_addr, size
                    );
                }

                stats.total_fdes += 1;
                let mut func_desc = FunctionDescriptor::new(None, start_addr, size);

                // Iterate through the unwind table
                process_fde(
                    &unwind_section,
                    &bases,
                    &fde,
                    &mut func_desc,
                    verbose,
                    stats,
                )?;

                functions.insert(start_addr, func_desc);
            }
        }
    }

    Ok(functions)
}

fn process_fde<R, US>(
    unwind_section: &US,
    bases: &BaseAddresses,
    fde: &gimli::FrameDescriptionEntry<R>,
    func_desc: &mut FunctionDescriptor,
    verbose: bool,
    stats: &mut ConversionStats,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Reader,
    US: UnwindSection<R>,
{
    let mut ctx = UnwindContext::new();
    let mut table = fde.rows(unwind_section, bases, &mut ctx)?;

    let start_addr = fde.initial_address();

    while let Some(row) = table.next_row()? {
        let current_pc = row.start_address();
        let offset = current_pc.saturating_sub(start_addr);

        stats.total_rows += 1;

        if verbose {
            eprintln!("  Row at offset 0x{:x}", offset);
        }

        // Try to convert DWARF unwind info to framehop UnwindRuleX86_64
        match translate_row_to_unwind_rule(row) {
            Ok(unwind_rule) => {
                // Convert to SFrame
                let result = convert_unwind_rule(unwind_rule, offset as u32);
                match result {
                    ConversionResult::Single(fre) => {
                        func_desc.add_fre(fre);
                        stats.successful_fres += 1;
                    }
                    ConversionResult::Unsupported(reason) => {
                        stats.unsupported += 1;
                        if verbose {
                            eprintln!("  Unsupported: {}", reason);
                        }
                    }
                    ConversionResult::Skip(reason) => {
                        stats.skipped += 1;
                        if verbose {
                            eprintln!("  Skipped: {}", reason);
                        }
                    }
                }
            }
            Err(e) => {
                stats.translation_failures += 1;
                if verbose {
                    eprintln!("  Failed to translate: {:?}", e);
                }
            }
        }
    }

    Ok(())
}

/// Translate a DWARF unwind table row to a framehop UnwindRuleX86_64
/// This is adapted from framehop's x86_64/dwarf.rs
fn translate_row_to_unwind_rule<RO: gimli::ReaderOffset, UCS: UnwindContextStorage<RO>>(
    row: &gimli::UnwindTableRow<RO, UCS>,
) -> Result<UnwindRuleX86_64, ConversionError> {
    let cfa_rule = row.cfa();
    let bp_rule = row.register(X86_64::RBP);
    let ra_rule = row.register(X86_64::RA);

    translate_into_unwind_rule(cfa_rule, &bp_rule, &ra_rule)
}

#[derive(Debug)]
enum ConversionError {
    CfaIsExpression,
    CfaIsOffsetFromUnknownRegister,
    ReturnAddressRuleWithUnexpectedOffset,
    ReturnAddressRuleWasWeird,
    SpOffsetDoesNotFit,
    RegisterNotStoredRelativeToCfa,
    FpStorageOffsetDoesNotFit,
    FramePointerRuleDoesNotRestoreBp,
    FramePointerRuleHasStrangeBpOffset,
}

fn register_rule_to_cfa_offset<RO: gimli::ReaderOffset>(
    rule: &RegisterRule<RO>,
) -> Result<Option<i64>, ConversionError> {
    match *rule {
        RegisterRule::Undefined | RegisterRule::SameValue => Ok(None),
        RegisterRule::Offset(offset) => Ok(Some(offset)),
        _ => Err(ConversionError::RegisterNotStoredRelativeToCfa),
    }
}

fn translate_into_unwind_rule<RO: gimli::ReaderOffset>(
    cfa_rule: &CfaRule<RO>,
    bp_rule: &RegisterRule<RO>,
    ra_rule: &RegisterRule<RO>,
) -> Result<UnwindRuleX86_64, ConversionError> {
    match ra_rule {
        RegisterRule::Undefined => {
            return Ok(UnwindRuleX86_64::EndOfStack);
        }
        RegisterRule::Offset(offset) if *offset == -8 => {
            // Normal case
        }
        RegisterRule::Offset(_) => {
            return Err(ConversionError::ReturnAddressRuleWithUnexpectedOffset);
        }
        _ => {
            return Err(ConversionError::ReturnAddressRuleWasWeird);
        }
    }

    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            X86_64::RSP => {
                let sp_offset_by_8 =
                    u16::try_from(offset / 8).map_err(|_| ConversionError::SpOffsetDoesNotFit)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(bp_rule)?;
                match fp_cfa_offset {
                    None => Ok(UnwindRuleX86_64::OffsetSp { sp_offset_by_8 }),
                    Some(bp_cfa_offset) => {
                        let bp_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + bp_cfa_offset) / 8)
                                .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleX86_64::OffsetSpAndRestoreBp {
                            sp_offset_by_8,
                            bp_storage_offset_from_sp_by_8,
                        })
                    }
                }
            }
            X86_64::RBP => {
                let bp_cfa_offset = register_rule_to_cfa_offset(bp_rule)?
                    .ok_or(ConversionError::FramePointerRuleDoesNotRestoreBp)?;
                if *offset == 16 && bp_cfa_offset == -16 {
                    Ok(UnwindRuleX86_64::UseFramePointer)
                } else {
                    Err(ConversionError::FramePointerRuleHasStrangeBpOffset)
                }
            }
            _ => Err(ConversionError::CfaIsOffsetFromUnknownRegister),
        },
        CfaRule::Expression(_) => Err(ConversionError::CfaIsExpression),
    }
}
