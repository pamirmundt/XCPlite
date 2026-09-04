//--------------------------------------------------------------------------------------------------------------------------------------------------
// Module dwarf
// Implements DebugDataReader, UnitList and functions to read DWARF debug information from ELF files
// Read ELF files and extract debug information
// Taken from Github repository a2ltool by DanielT

use indexmap::IndexMap;
use std::ffi::OsStr;
use std::ops::Index;
use std::{collections::HashMap, collections::HashSet, fs::File};

type SliceType<'a> = EndianSlice<'a, RunTimeEndian>;

use object::read::{ObjectSection, ObjectSymbol};
use object::{Endianness, Object};

use gimli::{Abbreviations, DebuggingInformationEntry, Dwarf, UnitHeader};
use gimli::{EndianSlice, RunTimeEndian};

use crate::elf_reader::debuginfo::cfa::{CfaInfo, get_cfa_from_object};
use crate::elf_reader::debuginfo::{DbgDataType, DebugData, TypeInfo, VarInfo};

mod attributes;
use attributes::{get_abstract_origin_attribute, get_linkage_name_attribute, get_location_attribute, get_name_attribute, get_specification_attribute, get_typeref_attribute};

mod typereader;

pub(crate) struct UnitList<'a> {
    list: Vec<(UnitHeader<SliceType<'a>>, gimli::Abbreviations)>,
}

struct DebugDataReader<'elffile> {
    dwarf: Dwarf<EndianSlice<'elffile, RunTimeEndian>>,
    verbose: usize,
    units: UnitList<'elffile>,
    unit_names: Vec<Option<String>>,
    endian: Endianness,
    sections: HashMap<String, (u64, u64)>,
    cfa_info: Vec<CfaInfo>,
    epk_string: Option<String>,
    epk_addr: u64,
    symbol_addresses: HashMap<String, u64>,
    xcp_meta_data: Option<(u64, Vec<u8>)>, // (section_base_addr, raw_bytes)
    is_little_endian: bool,
}

// Create DebugData
// Load and validate ELF/DWARF input, then collect and return parsed DebugData.
// This function constructs a temporary DebugDataReader that owns parser state
// (units, transient names, symbol table cache) and finalizes it into DebugData.
pub(crate) fn load_elf_dwarf(filename: &OsStr, verbose: usize, unit_idx_limit: usize) -> Result<DebugData, String> {
    log::debug!("load_elf_dwarf: {}", filename.to_string_lossy());

    // open the file and mmap its content
    let filedata = load_filedata(filename)?;

    // load the elf file using the object crate
    let elffile = load_elf_file(&filename.to_string_lossy(), &filedata, verbose)?;

    // print symbol table
    if verbose >= 1 {
        println!("\nSymbol table:");
        for symbol in elffile.symbols() {
            let Ok(name) = symbol.name() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            println!("  `{:?}`: addr={:x}, {:?}", name, symbol.address(), symbol);
        }
    }

    // verify that the elf file contains DWARF debug info
    if !elffile.sections().any(|section| section.name() == Ok(".debug_info")) {
        log::error!("DWARF .debug_info section not found");
        return Err(format!(
            "Error: {} does not contain DWARF2+ debug info. The section .debug_info is missing.",
            filename.to_string_lossy()
        ));
    }

    // load the DWARF sections from the elf file
    let dwarf = load_dwarf_sections(&elffile)?;

    // verify that the dwarf data is valid
    if !verify_dwarf_compile_units(&dwarf) {
        return Err(format!(
            "Error: {} does not contain DWARF2+ debug info - zero compile units contain debug info.",
            filename.to_string_lossy()
        ));
    }

    // get the elf sections for DebugDataReader
    let sections = get_elf_sections(&elffile);

    // read the EPK string and address from the xcp_epk ELF section
    let epk_section = elffile.section_by_name("xcp_epk");
    let epk_addr: u64 = epk_section.as_ref().map_or(0, |s| s.address());
    let epk_string: Option<String> = epk_section
        .and_then(|s| s.data().ok())
        .and_then(|data| std::ffi::CStr::from_bytes_until_nul(data).ok())
        .map(|cs| cs.to_string_lossy().into_owned());
    if let Some(ref epk) = epk_string {
        log::debug!("EPK string read from xcp_epk section: '{}' at address 0x{:08X}", epk, epk_addr);
    }

    // read the xcp_meta section raw bytes for metadata (XCP_UNIT / XCP_LIMITS annotations)
    let xcp_meta_section = elffile.section_by_name("xcp_meta");
    let xcp_meta_data: Option<(u64, Vec<u8>)> = xcp_meta_section.and_then(|s| {
        let addr = s.address();
        s.data().ok().map(|data| (addr, data.to_vec()))
    });
    if let Some((addr, ref data)) = xcp_meta_data {
        log::debug!("XCP metadata section (xcp_meta) found at address 0x{:08X}, {} bytes", addr, data.len());
    } else {
        log::debug!("XCP metadata section (xcp_meta) not found in ELF file");
    }
    let is_little_endian = elffile.endianness() == Endianness::Little;

    // get CFA information for DebugDataReader
    let mut cfa_info = Vec::new();
    let res = get_cfa_from_object(&elffile, &mut cfa_info, verbose, unit_idx_limit);
    match res {
        Ok(cfa) => {
            if cfa > 0 {
                log::debug!("CFA data found in {cfa} functions");
            } else {
                log::warn!("CFA data not found");
            }
        }
        Err(err) => {
            log::error!("CFA parser error: {err}");
        }
    }

    // create the debug data reader
    log::debug!("Creating debug data reader");
    let dbg_reader = DebugDataReader {
        dwarf,
        verbose,
        units: UnitList::new(),
        unit_names: Vec::new(),
        endian: elffile.endianness(),
        sections,
        cfa_info,
        epk_string,
        epk_addr,
        symbol_addresses: get_symbol_addresses(&elffile),
        xcp_meta_data,
        is_little_endian,
    };
    log::debug!("Reading debug info entries");
    Ok(dbg_reader.collect_debug_data(unit_idx_limit))
}

// open a file and mmap its content
fn load_filedata(filename: &OsStr) -> Result<memmap2::Mmap, String> {
    let file = match File::open(filename) {
        Ok(file) => file,
        Err(error) => {
            return Err(format!("Error: could not open file {}: {error}", filename.to_string_lossy()));
        }
    };

    match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => Ok(mmap),
        Err(err) => Err(format!("Error: Failed to map file '{}': {err}", filename.to_string_lossy())),
    }
}

// read the headers and sections of an elf/object file
fn load_elf_file<'data>(filename: &str, filedata: &'data [u8], verbose: usize) -> Result<object::read::File<'data>, String> {
    log::debug!("load_elf_file: {}", filename);
    match object::File::parse(filedata) {
        Ok(object_file) => {
            if verbose >= 1 {
                println!("\nParsed object file file: {}", filename);
                println!("ELF file format: {:?}", object_file.format());
                println!("Architecture: {:?}", object_file.architecture());
                println!("Endianness: {:?}", object_file.endianness());
                println!("\nSections:");
                for section in object_file.sections() {
                    let kind = section.kind();
                    println!(
                        "  Name: {:<20} Addr: 0x{:08x} Size: {} bytes Kind: {:?} ",
                        section.name().unwrap_or("<unknown>"),
                        section.address(),
                        section.size(),
                        kind
                    );
                }
                println!("\n");
            }

            Ok(object_file)
        }
        Err(err) => Err(format!("Error: Failed to parse file '{filename}': {err}")),
    }
}

fn get_elf_sections(elffile: &object::read::File) -> HashMap<String, (u64, u64)> {
    log::debug!("get_elf_sections: Creating ELF sections map for debug data (only size!=0 and addr!=0)");
    let mut map = HashMap::new();
    for section in elffile.sections() {
        let addr = section.address();
        let size = section.size();
        if addr != 0
            && size != 0
            && let Ok(name) = section.name()
        {
            map.insert(name.to_string(), (addr, addr + size));
            log::trace!("elf section: {} addr={addr:x}, size={size:x}", name);
        }
    }

    map
}

fn get_symbol_addresses(elffile: &object::read::File) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    for symbol in elffile.symbols() {
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let addr = symbol.address();
        if addr != 0 {
            map.insert(name.to_string(), addr);
        }
    }
    map
}

// load the DWARF debug info from the .debug_<xyz> sections
fn load_dwarf_sections<'data>(elffile: &object::read::File<'data>) -> Result<gimli::Dwarf<SliceType<'data>>, String> {
    log::debug!("load_dwarf_sections");
    // Dwarf::load takes two closures / functions and uses them to load all the required debug sections
    let loader = |section: gimli::SectionId| get_file_section_reader(elffile, section.name());
    gimli::Dwarf::load(loader)
}

// verify that the dwarf data is valid
fn verify_dwarf_compile_units(dwarf: &gimli::Dwarf<SliceType>) -> bool {
    let mut units_iter = dwarf.debug_info.units();
    let mut units_count = 0;
    while let Ok(Some(_)) = units_iter.next() {
        units_count += 1;
    }

    log::debug!("DWARF compile units: {}", units_count);
    units_count > 0
}

// get a section from the elf file.
// returns a slice referencing the section data if it exists, or an empty slice otherwise
fn get_file_section_reader<'data>(elffile: &object::read::File<'data>, section_name: &str) -> Result<SliceType<'data>, String> {
    if let Some(dbginfo) = elffile.section_by_name(section_name) {
        match dbginfo.data() {
            Ok(val) => Ok(EndianSlice::new(val, get_endian(elffile))),
            Err(e) => Err(e.to_string()),
        }
    } else {
        Ok(EndianSlice::new(&[], get_endian(elffile)))
    }
}

// get the endianity of the elf file
fn get_endian(elffile: &object::read::File) -> RunTimeEndian {
    if elffile.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big }
}

impl DebugDataReader<'_> {
    fn resolve_address_by_unique_suffix(&self, var_name: &str) -> Option<u64> {
        // Very short names are too ambiguous in mangled symbols.
        if var_name.len() < 4 {
            return None;
        }

        let mut matches = self
            .symbol_addresses
            .iter()
            .filter_map(|(symbol_name, addr)| if *addr != 0 && symbol_name.ends_with(var_name) { Some(*addr) } else { None });

        let first = matches.next()?;
        if matches.next().is_none() { Some(first) } else { None }
    }

    fn resolve_address_from_symbols(&self, entry: &DebuggingInformationEntry<SliceType, usize>, unit: &UnitHeader<SliceType>, var_name: &str) -> Option<u64> {
        if let Ok(linkage_name) = get_linkage_name_attribute(entry, &self.dwarf, unit)
            && let Some(addr) = self.symbol_addresses.get(&linkage_name).copied()
        {
            return Some(addr);
        }
        self.symbol_addresses.get(var_name).copied().or_else(|| self.resolve_address_by_unique_suffix(var_name))
    }

    // Traverse DWARF entries and finalize collected parser state into DebugData.
    fn collect_debug_data(mut self, unit_idx_limit: usize) -> DebugData {
        let variables = self.load_variables(unit_idx_limit);
        let (types, typenames) = self.load_types(&variables);
        let ambiguous_type_refs: HashSet<usize> = typenames
            .values()
            .filter(|type_refs| type_refs.len() > 1)
            .flatten()
            .copied()
            .collect();
        let qualified_type_names = self.load_qualified_type_names(&ambiguous_type_refs);
        let a2l_type_names = make_a2l_type_names(&typenames, &qualified_type_names);
        let varname_list: Vec<&String> = variables.keys().collect();
        let demangled_names = demangle_cpp_varnames(&varname_list);
        let unit_names = std::mem::take(&mut self.unit_names);

        DebugData {
            variables,
            types,
            typenames,
            a2l_type_names,
            demangled_names,
            unit_names,
            sections: self.sections,
            symbol_addresses: self.symbol_addresses,
            cfa_info: self.cfa_info,
            epk_string: self.epk_string,
            epk_addr: self.epk_addr,
            xcp_meta_data: self.xcp_meta_data,
            is_little_endian: self.is_little_endian,
        }
    }

    // load all variables from the dwarf data
    fn load_variables(&mut self, unit_idx_limit: usize) -> IndexMap<String, Vec<VarInfo>> {
        let mut variables = IndexMap::<String, Vec<VarInfo>>::new();

        let mut iter = self.dwarf.debug_info.units();
        while let Ok(Some(unit)) = iter.next() {
            // get the abbreviations for the unit
            let Ok(abbreviations) = unit.abbreviations(&self.dwarf.debug_abbrev) else {
                let offset = unit.offset().to_debug_info_offset(&unit).unwrap_or(gimli::DebugInfoOffset(0)).0;
                log::warn!("Failed to get abbreviations for unit @{offset:x}");
                continue;
            };

            // store the unit for later reference
            self.units.add(unit, abbreviations);
            let unit_idx = self.units.list.len() - 1;
            if unit_idx > unit_idx_limit {
                break;
            }
            let (unit, abbreviations) = &self.units[unit_idx];

            // The root of the tree inside of a unit is always a DW_TAG_compile_unit or DW_TAG_partial_unit.
            // The global variables are among the immediate children of the unit; static variables
            // in functions are declared inside of DW_TAG_subprogram[/DW_TAG_lexical_block]*.
            // We can easily find all of them by using depth-first traversal of the tree
            let mut entries_cursor = unit.entries(abbreviations);
            if let Ok(Some(entry)) = entries_cursor.next_dfs()
                && (entry.tag() == gimli::constants::DW_TAG_compile_unit || entry.tag() == gimli::constants::DW_TAG_partial_unit)
            {
                // @@@@ warn if unit name is missing
                let unit_name = match get_name_attribute(entry, &self.dwarf, unit) {
                    Ok(name) => {
                        log::trace!("unit name: {}", &name);
                        Some(name)
                    }
                    Err(e) => {
                        log::warn!("Failed to get unit name: {}", e);
                        None
                    }
                };
                self.unit_names.push(unit_name);
            }

            // traverse all entries in depth-first order
            let mut context: Vec<(gimli::DwTag, Option<String>)> = Vec::new();
            while let Ok(Some(entry)) = entries_cursor.next_dfs() {
                let depth = entry.depth();
                debug_assert!(depth >= 1);
                context.truncate((depth - 1) as usize);
                let tag = entry.tag();
                // It's essential to only get those names that might actually be needed.
                // Getting all names unconditionally doubled the runtime of the program
                // as a result of countless useless string allocations and deallocations.
                if tag == gimli::constants::DW_TAG_namespace || tag == gimli::constants::DW_TAG_subprogram {
                    context.push((tag, get_name_attribute(entry, &self.dwarf, unit).ok()));
                } else {
                    context.push((tag, None));
                }
                debug_assert_eq!(depth as usize, context.len());

                if entry.tag() == gimli::constants::DW_TAG_variable {
                    // Get variable information
                    match self.get_variable(entry, unit, abbreviations) {
                        Ok((name, typeref, address)) => {
                            let (function, namespaces) = get_varinfo_from_context(&context);
                            variables.entry(name).or_default().push(VarInfo {
                                address, // may be 0 for local variables
                                typeref,
                                unit_idx,
                                function,
                                namespaces,
                            });
                        }
                        Err(errmsg) => {
                            let offset = entry.offset().to_debug_info_offset(unit).unwrap_or(gimli::DebugInfoOffset(0)).0;
                            log::warn!("Could not load variable @{offset:x}: {errmsg}");
                        }
                    }
                }
            }
        }

        variables
    }

    fn load_qualified_type_names(&self, type_refs: &HashSet<usize>) -> HashMap<usize, String> {
        let mut qualified_type_names = HashMap::new();
        if type_refs.is_empty() {
            return qualified_type_names;
        }

        for (unit, abbreviations) in &self.units.list {
            let mut entries_cursor = unit.entries(abbreviations);
            let mut context: Vec<(gimli::DwTag, Option<String>)> = Vec::new();
            while let Ok(Some(entry)) = entries_cursor.next_dfs() {
                let depth = entry.depth();
                context.truncate(depth.saturating_sub(1) as usize);
                let tag = entry.tag();
                let type_ref = entry.offset().to_debug_info_offset(unit).map(|offset| offset.0);
                let entry_name = if is_named_scope(tag) || type_ref.is_some_and(|type_ref| type_refs.contains(&type_ref)) {
                    get_name_attribute(entry, &self.dwarf, unit).ok()
                } else {
                    None
                };

                if let (Some(type_ref), Some(type_name)) = (type_ref, &entry_name)
                    && type_refs.contains(&type_ref)
                {
                    qualified_type_names.insert(type_ref, make_qualified_type_name(&context, type_name));
                }
                context.push((tag, if is_named_scope(tag) { entry_name } else { None }));
            }
        }
        qualified_type_names
    }

    // Return global variable information
    // an entry of the type DW_TAG_variable only describes a global variable if there is a name, a type and an address
    // this function tries to get all three and returns them
    // returns None if the entry does not describe a global variable
    /*
        fn get_global_variable(
            &self,
            entry: &DebuggingInformationEntry<SliceType, usize>,
            unit: &UnitHeader<SliceType>,
            abbrev: &gimli::Abbreviations,
        ) -> Result<Option<(String, usize, u64)>, String> {
            match get_location_attribute(self, entry, unit.encoding(), &self.units.list.len() - 1) {
                Some((addr_ext, addr)) => {
                    // if debugging information entry A has a DW_AT_specification or DW_AT_abstract_origin attribute
                    // pointing to another debugging information entry B, any attributes of B are considered to be part of A.
                    if let Some(specification_entry) = get_specification_attribute(entry, unit, abbrev) {
                        // the entry refers to a specification, which contains the name and type reference
                        let name = get_name_attribute(&specification_entry, &self.dwarf, unit)?;
                        let typeref = get_typeref_attribute(&specification_entry, unit)?;
                        Ok(Some((name, typeref, addr)))
                    } else if let Some(abstract_origin_entry) = get_abstract_origin_attribute(entry, unit, abbrev) {
                        // the entry refers to an abstract origin, which should also be considered when getting the name and type ref
                        let name = get_name_attribute(entry, &self.dwarf, unit).or_else(|_| get_name_attribute(&abstract_origin_entry, &self.dwarf, unit))?;
                        let typeref = get_typeref_attribute(entry, unit).or_else(|_| get_typeref_attribute(&abstract_origin_entry, unit))?;
                        Ok(Some((name, typeref, addr)))
                    } else {
                        // usual case: there is no specification or abstract origin and all info is part of this entry
                        let name = get_name_attribute(entry, &self.dwarf, unit)?;
                        let typeref = get_typeref_attribute(entry, unit)?;
                        Ok(Some((name, typeref, addr)))
                    }
                }
                None => {
                    // it's a local variable, skip, no error
                    Ok(None)
                }
            }
        }
    */

    // @@@@ xcp_client: Get all variables, including local variables
    // Return variable information
    // returns name, type reference and address
    // address may be 0 if a local variable is requested
    fn get_variable<'a>(
        &self,
        entry: &DebuggingInformationEntry<SliceType<'a>, usize>,
        unit: &UnitHeader<SliceType<'a>>,
        abbrev: &gimli::Abbreviations,
    ) -> Result<(String, usize, (u8, u64)), String> {
        // if debugging information entry A has a DW_AT_specification or DW_AT_abstract_origin attribute
        // pointing to another debugging information entry B, any attributes of B are considered to be part of A.
        if let Some(specification_entry) = get_specification_attribute(entry, unit, abbrev) {
            // the entry refers to a specification, which contains the name and type reference
            let name = get_name_attribute(&specification_entry, &self.dwarf, unit)?;
            log::debug!("get_variable '{}':", name);
            let typeref = get_typeref_attribute(&specification_entry, unit)?;
            let mut address = get_location_attribute(self, entry, unit.encoding(), &self.units.list.len() - 1).unwrap_or((0u8, 0u64));
            if address == (0u8, 0u64)
                && let Some(sym_addr) = self
                    .resolve_address_from_symbols(entry, unit, &name)
                    .or_else(|| self.resolve_address_from_symbols(&specification_entry, unit, &name))
            {
                address = (0u8, sym_addr);
            }
            if address.0 >= 0x80 {
                log::debug!("  {} is a register, tls or has unknown location", name);
            } else if address.1 == 0 {
                log::debug!("  {} has no address", name);
            }
            Ok((name, typeref, address))
        } else if let Some(abstract_origin_entry) = get_abstract_origin_attribute(entry, unit, abbrev) {
            // the entry refers to an abstract origin, which should also be considered when getting the name and type ref
            let name = get_name_attribute(entry, &self.dwarf, unit).or_else(|_| get_name_attribute(&abstract_origin_entry, &self.dwarf, unit))?;
            log::debug!("'{}':", name);
            let typeref = get_typeref_attribute(entry, unit).or_else(|_| get_typeref_attribute(&abstract_origin_entry, unit))?;
            let mut address = get_location_attribute(self, entry, unit.encoding(), &self.units.list.len() - 1).unwrap_or((0u8, 0u64));
            if address == (0u8, 0u64)
                && let Some(sym_addr) = self
                    .resolve_address_from_symbols(entry, unit, &name)
                    .or_else(|| self.resolve_address_from_symbols(&abstract_origin_entry, unit, &name))
            {
                address = (0u8, sym_addr);
            }
            if address.0 >= 0x80 {
                log::debug!("  {} is a register, tls or has unknown location", name);
            } else if address.1 == 0 {
                log::debug!("  {} has no address", name);
            }
            Ok((name, typeref, address))
        } else {
            // usual case: there is no specification or abstract origin and all info is part of this entry
            let name = get_name_attribute(entry, &self.dwarf, unit)?;
            log::debug!("'{}':", name);
            let typeref = get_typeref_attribute(entry, unit)?;
            let mut address = get_location_attribute(self, entry, unit.encoding(), &self.units.list.len() - 1).unwrap_or((0u8, 0u64));
            if address == (0u8, 0u64)
                && let Some(sym_addr) = self.resolve_address_from_symbols(entry, unit, &name)
            {
                address = (0u8, sym_addr);
            }
            if address.0 >= 0x80 {
                log::debug!("  {} is a register, tls or has unknown location", name);
            } else if address.1 == 0 {
                log::debug!(". {} has no address", name);
            }
            Ok((name, typeref, address))
        }
    }
}

fn get_varinfo_from_context(context: &[(gimli::DwTag, Option<String>)]) -> (Option<String>, Vec<String>) {
    let function = context
        .iter()
        .rev()
        .find(|(tag, _)| *tag == gimli::constants::DW_TAG_subprogram)
        .and_then(|(_, name)| name.clone());
    let namespaces: Vec<String> = context
        .iter()
        .rev()
        .filter_map(|(tag, ns)| (*tag == gimli::constants::DW_TAG_namespace).then(|| ns.clone()).flatten())
        .collect();
    (function, namespaces)
}

fn is_named_scope(tag: gimli::DwTag) -> bool {
    matches!(
        tag,
        gimli::constants::DW_TAG_namespace
            | gimli::constants::DW_TAG_subprogram
            | gimli::constants::DW_TAG_structure_type
            | gimli::constants::DW_TAG_class_type
            | gimli::constants::DW_TAG_union_type
    )
}

fn make_qualified_type_name(context: &[(gimli::DwTag, Option<String>)], type_name: &str) -> String {
    let mut qualified_name = context
        .iter()
        .filter(|(tag, _)| is_named_scope(*tag))
        .filter_map(|(_, name)| name.as_deref())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    if !qualified_name.is_empty() {
        qualified_name.push('.');
    }
    qualified_name.push_str(type_name);
    qualified_name
}

fn make_a2l_type_names(typenames: &HashMap<String, Vec<usize>>, qualified_type_names: &HashMap<usize, String>) -> HashMap<usize, String> {
    let mut a2l_type_names = HashMap::new();
    for type_refs in typenames.values() {
        let mut names = type_refs.iter().filter_map(|type_ref| qualified_type_names.get(type_ref));
        let Some(first_name) = names.next() else {
            continue;
        };
        if names.any(|name| name != first_name) {
            for type_ref in type_refs {
                if let Some(name) = qualified_type_names.get(type_ref) {
                    a2l_type_names.insert(*type_ref, name.clone());
                }
            }
        }
    }
    a2l_type_names
}

fn demangle_cpp_varnames(input: &[&String]) -> HashMap<String, String> {
    let mut demangled_symbols = HashMap::<String, String>::new();
    let demangle_opts = cpp_demangle::DemangleOptions::new().no_params().no_return_type();
    for varname in input {
        // some really simple strings can be processed by the demangler, e.g "c" -> "const", which is wrong here.
        // by only processing symbols that start with _Z (variables in classes/namespaces) this problem is avoided
        if varname.starts_with("_Z")
            && let Ok(sym) = cpp_demangle::Symbol::new(*varname)
        {
            // exclude useless demangled names like "typeinfo for std::type_info" or "{vtable(std::type_info)}"
            if let Ok(demangled) = sym.demangle_with_options(&demangle_opts)
                && !demangled.contains(' ')
                && !demangled.starts_with("{vtable")
            {
                demangled_symbols.insert(demangled, (*varname).clone());
            }
        }
    }

    demangled_symbols
}

// UnitList holds a list of all UnitHeaders in the Dwarf data for convenient access
impl<'a> UnitList<'a> {
    fn new() -> Self {
        Self { list: Vec::new() }
    }

    fn add(&mut self, unit: UnitHeader<SliceType<'a>>, abbrev: Abbreviations) {
        self.list.push((unit, abbrev));
    }

    fn get_unit(&self, itemoffset: usize) -> Option<usize> {
        for (idx, (unit, _)) in self.list.iter().enumerate() {
            let unitoffset = unit.offset().to_debug_info_offset(unit).unwrap().0;
            if unitoffset < itemoffset && unitoffset + unit.length_including_self() > itemoffset {
                return Some(idx);
            }
        }

        None
    }
}

impl<'a> Index<usize> for UnitList<'a> {
    type Output = (UnitHeader<SliceType<'a>>, gimli::Abbreviations);

    fn index(&self, idx: usize) -> &Self::Output {
        &self.list[idx]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // C++ type test fixture, see fixtures/cpp_types.cpp
    static ELF_FILE_NAMES: [&str; 1] = [concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/cpp_types.elf")];

    #[test]
    fn test_make_qualified_type_name() {
        let context = vec![
            (gimli::constants::DW_TAG_compile_unit, None),
            (gimli::constants::DW_TAG_namespace, Some("namespace_1".to_string())),
            (gimli::constants::DW_TAG_class_type, Some("Controller".to_string())),
        ];

        assert_eq!(make_qualified_type_name(&context, "TypeA"), "namespace_1.Controller.TypeA");
    }

    #[test]
    fn test_make_a2l_type_names() {
        let typenames = HashMap::from([("TypeA".to_string(), vec![1, 2]), ("TypeB".to_string(), vec![3, 4])]);
        let qualified_type_names = HashMap::from([
            (1, "namespace_1.TypeA".to_string()),
            (2, "namespace_2.TypeA".to_string()),
            (3, "common.TypeB".to_string()),
            (4, "common.TypeB".to_string()),
        ]);
        let a2l_type_names = make_a2l_type_names(&typenames, &qualified_type_names);
        assert_eq!(a2l_type_names.get(&1).map(String::as_str), Some("namespace_1.TypeA"));
        assert_eq!(a2l_type_names.get(&2).map(String::as_str), Some("namespace_2.TypeA"));
        assert!(!a2l_type_names.contains_key(&3));
        assert!(!a2l_type_names.contains_key(&4));
    }

    #[test]
    fn test_load_data() {
        for filename in ELF_FILE_NAMES {
            let debugdata = DebugData::load_dwarf(OsStr::new(filename), 1, usize::MAX).unwrap();
            // 14 globals in cpp_types.cpp, compilers may add a few more (e.g. static members)
            assert!(debugdata.variables.len() >= 14, "only {} variables found", debugdata.variables.len());
            assert!(debugdata.variables.get("g_sink").is_some());

            for (_, varinfo) in &debugdata.variables {
                assert!(debugdata.types.contains_key(&varinfo[0].typeref));
            }

            let datatype_of = |name: &str| -> &DbgDataType {
                let varinfo = debugdata.variables.get(name).unwrap_or_else(|| panic!("variable {name} not found"));
                &debugdata.types.get(&varinfo[0].typeref).unwrap().datatype
            };
            assert!(matches!(datatype_of("g_plain"), DbgDataType::Struct { is_class: false, .. }));
            assert!(matches!(datatype_of("g_pubclass"), DbgDataType::Struct { is_class: true, .. }));
            assert!(matches!(datatype_of("g_bigenum"), DbgDataType::Enum { signed: true, .. }));

            /*
            if let TypeInfo {
                datatype: DbgDataType::Class { inheritance, members, .. },
                ..
            } = typeinfo
            {
                assert!(inheritance.contains_key("base1"));
                assert!(inheritance.contains_key("base2"));
                assert!(matches!(
                    members.get("ss"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Sint16,
                            ..
                        },
                        _
                    ))
                ));
                assert!(matches!(
                    members.get("base1_var"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Sint32,
                            ..
                        },
                        _
                    ))
                ));
                assert!(matches!(
                    members.get("base2var"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Sint32,
                            ..
                        },
                        _
                    ))
                ));
            }

            let varinfo = debugdata.variables.get("class2").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Class { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("class3").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Class { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("class4").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Class { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("staticvar").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Sint32,
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("structvar").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Struct { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("bitfield").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Struct { .. },
                    ..
                }
            ));
            if let TypeInfo {
                datatype: DbgDataType::Struct { members, .. },
                ..
            } = typeinfo
            {
                assert!(matches!(
                    members.get("var"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Bitfield { bit_offset: 0, bit_size: 5, .. },
                            ..
                        },
                        0
                    ))
                ));
                assert!(matches!(
                    members.get("var2"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Bitfield { bit_offset: 5, bit_size: 5, .. },
                            ..
                        },
                        0
                    ))
                ));
                assert!(matches!(
                    members.get("var3"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Bitfield { bit_offset: 0, bit_size: 23, .. },
                            ..
                        },
                        4
                    ))
                ));
                assert!(matches!(
                    members.get("var4"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Bitfield { bit_offset: 23, bit_size: 1, .. },
                            ..
                        },
                        4
                    ))
                ));
            }
            let varinfo = debugdata.variables.get("enum_var1").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Enum { .. },
                    ..
                }
            ));
            let varinfo = debugdata.variables.get("enum_var2").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Enum { .. },
                    ..
                }
            ));
            let varinfo = debugdata.variables.get("enum_var3").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Enum { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("var_array").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            let DbgDataType::Array { size, dim, arraytype, .. } = &typeinfo.datatype else {
                panic!("Expected array type, got {:?}", typeinfo.datatype);
            };
            assert_eq!(*size, 33);
            assert_eq!(dim.len(), 1);
            assert_eq!(dim[0], 33);
            assert!(matches!(arraytype.datatype, DbgDataType::Uint8));

            let varinfo = debugdata.variables.get("var_multidim").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            let DbgDataType::Array { dim, arraytype, .. } = &typeinfo.datatype else {
                panic!("Expected array type, got {:?}", typeinfo.datatype);
            };
            assert_eq!(dim.len(), 3);
            assert_eq!(dim, &[10, 3, 7]);
            assert!(matches!(arraytype.datatype, DbgDataType::Float));
            */
        }
    }
}
