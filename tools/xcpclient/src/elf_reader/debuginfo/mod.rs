//--------------------------------------------------------------------------------------------------------------------------------------------------
// Module debuginfo
// Implements DebugData, VarInfo, TypeInfo and DbgDataType
// Read ELF files and extract debug information

// Based on Github repository a2ltool by DanielT: https://github.com/DanielT/a2ltool

/* 
Note on V2.1.10:
Updated to typereader.rs from a2ltool v3.4.1 (commit 0b61aa5, 2026-08-04).
The Class variant is gone. 
Struct now carries is_class and inheritance, and the size and Display code follow.
*/


use indexmap::IndexMap;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::Display;

mod dwarf;

mod cfa;
use cfa::CfaInfo;

// VarInfo holds information about a variable
#[derive(Debug)]
pub(crate) struct VarInfo {
    pub(crate) address: (u8, u64),       // addr_ext, addr
    pub(crate) typeref: usize,           // reference to TypeInfo in DebugData.types
    pub(crate) unit_idx: usize,          // compilation unit index
    pub(crate) function: Option<String>, // function name if variable is local to a function
    pub(crate) namespaces: Vec<String>,  // namespaces the variable is defined in
}

// TypeInfo holds information about a variable's type
// get_size - returns the size of the type in bytes
// Display - formats the type information as a string
#[derive(Debug, Clone)]
pub(crate) struct TypeInfo {
    pub(crate) name: Option<String>,  // not all types have a name
    pub(crate) unit_idx: usize,       // compilation unit index
    pub(crate) datatype: DbgDataType, // the actual type information
    pub(crate) dbginfo_offset: usize, // offset in the debug info section
}

#[derive(Debug, Clone)]
pub(crate) enum DbgDataType {
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Sint8,
    Sint16,
    Sint32,
    Sint64,
    Float,
    Double,
    Bitfield {
        basetype: Box<TypeInfo>,
        bit_offset: u16,
        bit_size: u16,
    },
    Pointer(u64, usize),
    /// A struct or a class. There is no practical difference between them, both can have base classes in C++;
    /// `is_class` only affects the displayed name. Inherited members are also copied into `members` with adjusted offsets.
    Struct {
        size: u64,
        is_class: bool,
        inheritance: IndexMap<String, (TypeInfo, u64)>,
        members: IndexMap<String, (TypeInfo, u64)>,
    },
    Union {
        size: u64,
        members: IndexMap<String, (TypeInfo, u64)>,
    },
    Enum {
        size: u64,
        signed: bool,
        enumerators: Vec<(String, i64)>,
    },
    Array {
        size: u64,
        dim: Vec<u64>,
        stride: u64,
        arraytype: Box<TypeInfo>,
    },
    TypeRef(usize, u64), // dbginfo_offset of the referenced type
    FuncPtr(u64),
    Other(u64),
}

// holds the debug information from an ELF file
#[derive(Debug)]
pub(crate) struct DebugData {
    pub(crate) variables: IndexMap<String, Vec<VarInfo>>, // variable name -> list of VarInfo for instances with that name
    pub(crate) types: HashMap<usize, TypeInfo>,           // type reference -> TypeInfo
    pub(crate) typenames: HashMap<String, Vec<usize>>,    // type name -> list of type references
    pub(crate) a2l_type_names: HashMap<usize, String>,    // type reference -> qualified A2L name, only for ambiguous type names
    pub(crate) demangled_names: HashMap<String, String>,  // mangled name -> demangled name
    pub(crate) unit_names: Vec<Option<String>>,           // list of compilation unit names by unit index
    pub(crate) sections: HashMap<String, (u64, u64)>,     // section name -> (start, end)
    pub(crate) symbol_addresses: HashMap<String, u64>,    // ELF symbol name -> address
    pub(crate) cfa_info: Vec<CfaInfo>,                    // CFA information for functions which contain an event trigger, the CFA is valid for  the location of the event trigger
    pub(crate) epk_string: Option<String>,                // EPK string read from xcp_epk ELF section
    pub(crate) epk_addr: u64,                             // Address of the xcp_epk ELF section (0 if not found)
    pub(crate) xcp_meta_data: Option<(u64, Vec<u8>)>,     // (section_base_addr, raw_bytes) of xcp_meta section
    pub(crate) is_little_endian: bool,                    // ELF endianness
}

// load_dwarf - loads and parses the DWARF debug information from an ELF file
// make_simple_unit_name - converts a full unit name to a simple unit name
// print_debug_info - prints the debug information to the console
// print_debug_stats - prints a summary of the debug information
impl DebugData {
    /// load the debug info from an elf file
    pub(crate) fn load_dwarf(filename: &OsStr, verbose: usize, unit_idx_limit: usize) -> Result<Self, String> {
        dwarf::load_elf_dwarf(filename, verbose, unit_idx_limit)
    }

    /// convert a full unit name, which might include a path, into a simple unit name
    pub(crate) fn make_simple_unit_name(&self, unit_idx: usize) -> Option<String> {
        let full_name = self.unit_names.get(unit_idx)?.as_deref()?;
        let file_name = if let Some(pos) = full_name.rfind('\\') {
            &full_name[(pos + 1)..]
        } else if let Some(pos) = full_name.rfind('/') {
            &full_name[(pos + 1)..]
        } else {
            full_name
        };

        Some(file_name.replace('.', "_"))
    }

    /// Return the shortest unambiguous A2L name for a DWARF type.
    pub(crate) fn get_a2l_type_name<'a>(&'a self, type_info: &'a TypeInfo) -> Option<&'a str> {
        let type_name = type_info.name.as_deref()?;
        Some(self.a2l_type_names.get(&type_info.dbginfo_offset).map_or(type_name, String::as_str))
    }

    // Get the address of the XCP event descriptor memory section
    pub(crate) fn get_event_section_addr(&self) -> u64 {
        // Find section 'xcp_evts'
        if let Some((start, end)) = self.sections.get("xcp_evts") {
            log::info!("Found XCP event descriptor memory section at address = 0x{:08X}, size = {} bytes", start, end - start);
            return *start;
        }

        // Some linker scripts merge the xcp_evts input section into another output
        // section. In that case, use the boundary symbols generated by the linker.
        if let (Some(start), Some(stop)) = (self.symbol_addresses.get("__start_xcp_evts"), self.symbol_addresses.get("__stop_xcp_evts")) {
            if start < stop {
                log::info!(
                    "Found XCP event descriptors using linker symbols at address = 0x{:08X}, size = {} bytes",
                    start,
                    stop - start
                );
                return *start;
            }
            log::warn!("Invalid XCP event descriptor linker symbol range: start = 0x{:08X}, stop = 0x{:08X}", start, stop);
        }

        log::warn!("XCP event descriptor memory section (xcp_evts) and linker boundary symbols not found");
        0
    }

    // Get the address of the XCP EPK memory section
    pub(crate) fn get_epk_section_addr(&self) -> u64 {
        let sections: Vec<(&String, &(u64, u64))> = self.sections.iter().collect();
        for (name, (addr, size)) in sections {
            if name == "xcp_epk" {
                log::info!("Found XCP EPK memory section at address = 0x{:08X}, size = {} bytes", *addr, *size);
                return *addr;
            }
        }

        log::warn!("XCP epk descriptor memory section (xcp_epk) not found");
        return 0;
    }

    /// print the debug statistics
    pub(crate) fn print_debug_stats(&self) {
        println!("\n====================================================================================================");
        println!("DebugData information summary:");
        println!("  Compilation units: {} units", self.unit_names.len());
        println!("  Sections: {} sections", self.sections.len());
        print!("  Endianness: ");
        if self.is_little_endian {
            println!("Little Endian");
        } else {
            println!("Big Endian");
        }
        let mut variable_count = 0;
        for (name, var_infos) in &self.variables {
            variable_count += var_infos.len();
        }
        println!("  Variables {} with {} unique names", variable_count, self.variables.len());
        println!("  Demangled names: {} entries", self.demangled_names.len());
        println!("  Type names: {} named types", self.typenames.len());
        println!("  Types: {} total types", self.types.len());
        println!("  CFA info: {} entries", self.cfa_info.len());
        println!("  EPK string: `{}` at address 0x{:08X}", self.epk_string.as_deref().unwrap_or("<not found>"), self.epk_addr);
        if let Some((addr, data)) = &self.xcp_meta_data {
            println!("  XCP metadata section (xcp_meta) found at address 0x{:08X}, {} bytes", addr, data.len());
        } else {
            println!("  XCP metadata section (xcp_meta) not found");
        }
    }

    // level 0 .. 5 stats, variables, variable types, demangled names, type names, types
    // level >= 1 print variables
    // level >= 2 print variable types
    // level >= 3 print demangled names
    // level >= 4 print type names
    // level >= 5 print types
    pub(crate) fn print_debug_info(&self, level: usize, unit_idx_limit: usize) {
        //
        self.print_debug_stats();

        //Print all compilation units
        println!("\n====================================================================================================");
        println!("Compilation units in debug_data.unit_names:");
        for (idx, unit_name) in self.unit_names.iter().enumerate() {
            let unit_name = self.make_simple_unit_name(idx);
            if unit_name.is_none() {
                println!("  Unit {}: <unnamed>", idx);
            } else {
                println!("  Unit {}: {}", idx, unit_name.as_ref().unwrap());
            }
        }
        println!();

        // Print sections sorted by address
        println!("\n====================================================================================================");
        println!("Memory Sections in debug_data.sections:");
        let mut sections: Vec<(&String, &(u64, u64))> = self.sections.iter().collect();
        sections.sort_by_key(|&(_, (addr, _))| *addr);
        let mut last_addr: u64 = 0;
        for (name, (addr, size)) in sections {
            println!("  '{}': 0x{:08x}, {} bytes ({})", name, *addr, *addr - last_addr, *size);
            last_addr = *addr;
        }

        if level >= 4 {
            //Print type names
            println!("\n====================================================================================================");
            println!("Type names in debug_data.typenames:");
            for (type_name, type_refs) in &self.typenames {
                println!("Type name '{}': {} references", type_name, type_refs.len());
                for type_ref in type_refs {
                    if let Some(type_info) = self.types.get(type_ref) {
                        println!("  -> type_ref={}, size={} bytes, unit={}", type_ref, type_info.get_size(), type_info.unit_idx);
                    }
                }
            }

            if level >= 5 {
                // Print types
                println!("\n====================================================================================================");
                println!("Types in debug_data.types:");
                for (type_ref, type_info) in &self.types {
                    let type_name = if let Some(name) = &type_info.name { name } else { "" };
                    println!(
                        "TypeRef {}: name = '{}', size = {} bytes, unit = {}, type={}",
                        type_ref,
                        type_name,
                        type_info.get_size(),
                        type_info.unit_idx,
                        type_info
                    );
                }
            }

            // Print demangled names
            if level >= 3 {
                println!("\n====================================================================================================");
                println!("\nDemangled Names:");
                for (mangled_name, demangled_name) in &self.demangled_names {
                    println!("  '{}' -> '{}'", mangled_name, demangled_name);
                }
            }
        }

        // Print A2L Creator variables
        println!("\n====================================================================================================");
        println!("A2L Creator variables:");
        for (var_name, var_info) in &self.variables {
            if var_name.starts_with("xcp_meta__")
                || var_name.starts_with("calblk__")
                || var_name.starts_with("calseg__")
                || var_name.starts_with("evt__")
                || var_name.starts_with("trg__")
            {
                if var_info.len() != 1 {
                    println!("{} instances of '{}' found, skipped", var_info.len(), var_name);
                    continue;
                }
                let var = &var_info[0];
                let unit_name = if let Some(name) = self.make_simple_unit_name(var.unit_idx) {
                    name
                } else {
                    "<unnamed>".to_string()
                };
                let function_name = if let Some(name) = &var.function { name } else { "<global>" };
                let name_space = if var.namespaces.len() > 0 { var.namespaces.join("::") } else { "".to_string() };
                println!(
                    "{}':  {}:'{}' {}: addr={}:0x{:08X}",
                    var_name, unit_name, function_name, name_space, var.address.0, var.address.1
                );
            }
        }

        // Print all variables
        if level >= 2 {
            println!("\n====================================================================================================");
            println!("Variables:");
            println!("  (Skipping system variables '__<name>' and global XCP variables 'gXcp..' and 'gA2l..')");

            for (var_name, var_info) in &self.variables {
                // Count all variable in unit_idx
                let count = var_info.iter().filter(|v| v.unit_idx <= unit_idx_limit).count();

                // Skip standard library variables and system/compiler internals (__<name>)s
                // Skip global XCP variables (gXCP.. and gA2L..)
                if level < 5 && var_name.starts_with("__") || var_name.starts_with("gXcp") || var_name.starts_with("gA2l") {
                    continue;
                }

                // print only variables from compilation unit 0..=unit_idx
                if count == 1 && var_info[0].unit_idx > unit_idx_limit {
                    continue;
                }

                // Iterate over all variable infos for this variable name in unit_idx
                if level >= 2 {
                    println!("{} {}: ", var_name, count);
                } else if level >= 3 {
                    if count > 1 {
                        println!("{} {}: ", var_name, count);
                    }
                    for var in var_info {
                        // print only variables from compilation unit 0..=unit_idx
                        if var.unit_idx > unit_idx_limit {
                            continue; // print only variables from compilation unit 0..=unit_idx
                        }
                        if count <= 1 {
                            print!("{} : ", var_name);
                        }
                        let unit_name = if let Some(name) = self.make_simple_unit_name(var.unit_idx) {
                            name
                        } else {
                            "<unnamed>".to_string()
                        };
                        let function_name = if let Some(name) = &var.function { name } else { "<global>" };
                        let name_space = if var.namespaces.len() > 0 { var.namespaces.join("::") } else { "".to_string() };
                        print!(" {}:'{}' {}: addr={}:0x{:08X}", unit_name, function_name, name_space, var.address.0, var.address.1);
                        if let Some(type_info) = self.types.get(&var.typeref) {
                            let type_name = if let Some(name) = &type_info.name { name } else { "" };
                            print!(", type='{}', size={}", type_name, type_info.get_size());
                        }
                        println!();
                    }
                }
            }
        }

        // Print all functions with CFA info
        // println!("\n====================================================================================================");
        // println!("Functions:");
        // for (i, func) in self.cfa_info.iter().enumerate() {
        //     println!("\nFunction #{}: {}", i + 1, func.function);
        //     println!("  Compilation Unit: {}", func.unit_idx);
        //     println!(
        //         "  Address Range: 0x{:08x} - 0x{:08x} (size: {} bytes)",
        //         func.low_pc,
        //         func.high_pc,
        //         func.high_pc - func.low_pc
        //     );
        //     match func.cfa_offset {
        //         Some(offset) => {
        //             println!("  CFA Offset: {} (0x{:x})", offset, offset);
        //             println!("  Local variables are likely at: CFA + {} + variable_offset", offset);
        //         }
        //         None => {
        //             println!("  CFA Offset: Unknown - may require complex DWARF expression evaluation");
        //             println!("  Note: This might indicate a more complex frame layout");
        //         }
        //     }
        // }

        // Print all functions grouped by compilation unit
        if level >= 2 {
            println!("\n====================================================================================================");
            println!("Functions and CFA information by compilation unit:");
            let mut by_cu: HashMap<usize, Vec<&CfaInfo>> = HashMap::new();
            for func in &self.cfa_info {
                by_cu.entry(func.unit_idx).or_default().push(func);
            }
            for (cu_idx, cu_functions) in by_cu {
                println!("Compilation Unit {}: {} functions", cu_idx, cu_functions.len());
                for func in cu_functions {
                    let cfa_info = match func.cfa_offset {
                        Some(offset) => format!("CFA+{}", offset),
                        None => "CFA unknown".to_string(),
                    };
                    println!("  {} (0x{:08x}-0x{:08x}) [{}]", func.function, func.low_pc, func.high_pc, cfa_info);
                }
            }
        }
    }
}

// TypeInfo holds information about a variable's type
impl TypeInfo {
    pub(crate) fn get_size(&self) -> u64 {
        match &self.datatype {
            DbgDataType::Uint8 => 1,
            DbgDataType::Uint16 => 2,
            DbgDataType::Uint32 => 4,
            DbgDataType::Uint64 => 8,
            DbgDataType::Sint8 => 1,
            DbgDataType::Sint16 => 2,
            DbgDataType::Sint32 => 4,
            DbgDataType::Sint64 => 8,
            DbgDataType::Float => 4,
            DbgDataType::Double => 8,
            DbgDataType::Bitfield { basetype, .. } => basetype.get_size(),
            DbgDataType::Pointer(size, _)
            | DbgDataType::Other(size)
            | DbgDataType::Struct { size, .. }
            | DbgDataType::Union { size, .. }
            | DbgDataType::Enum { size, .. }
            | DbgDataType::Array { size, .. }
            | DbgDataType::FuncPtr(size)
            | DbgDataType::TypeRef(_, size) => *size,
        }
    }
}

impl Display for TypeInfo {
    /*


        /// print detailed type information
        pub(crate) fn print_type_info(&self, type_info: &TypeInfo) {
            let type_name = if let Some(name) = &type_info.name { name } else { "" };
            let type_size = type_info.get_size();

            print!("    TypeInfo: {}", type_name);
            // print!(" (unit_idx = {}, dbginfo_offset = {})",type_info.unit_idx, type_info.dbginfo_offset);

            match &type_info.datatype {
                DbgDataType::Uint8 | DbgDataType::Uint16 | DbgDataType::Uint32 | DbgDataType::Uint64 => {
                    println!(" Integer: {} byte unsigned", type_size);
                }
                DbgDataType::Sint8 | DbgDataType::Sint16 | DbgDataType::Sint32 | DbgDataType::Sint64 => {
                    println!(" Integer: {} byte signed", type_size);
                }
                DbgDataType::Float | DbgDataType::Double => {
                    println!(" Floating point: {} byte", type_size);
                }

                DbgDataType::Pointer(typeref, size) => {
                    println!(" Pointer: typeref = {}, size = {} ", typeref, size);
                }
                DbgDataType::Array { arraytype, dim, stride, size } => {
                    println!(" Array: typeref = {}, dim = {:?}, stride = {} bytes, size = {} bytes", arraytype, dim, stride, size);
                }
                DbgDataType::Struct { size, members } => {
                    println!(" Struct: {} fields, size = {}", members.len(), size);
                    for (name, (type_info, member_offset)) in members {
                        let member_size = type_info.get_size();
                        println!("      Field '{}': size = {} bytes, offset = {} bytes", name, member_size, member_offset);
                    }
                }
                DbgDataType::Union { members, size } => {
                    println!(" Union: {} members, size = {} bytes", members.len(), size);
                }
                DbgDataType::Enum { size, signed, enumerators } => {
                    println!(" Enum: {} variants, size = {} bytes", enumerators.len(), size);
                    for (name, value) in enumerators {
                        println!("      Variant '{}': value={}", name, value);
                    }
                }
                DbgDataType::Bitfield { basetype, bit_offset, bit_size } => {
                    println!(" Bitfield: base type = {:?}, offset = {} bits, size = {} bits", basetype.datatype, bit_offset, bit_size);
                }
                DbgDataType::Class { size, inheritance, members } => {
                    println!(" Class: {} members, size = {} bytes", members.len(), size);
                }
                DbgDataType::FuncPtr(size) => {
                    println!(" Function pointer: size = {} bytes", size);
                }
                DbgDataType::TypeRef(typeref, size) => {
                    println!(" TypeRef: typeref = {}, size = {} bytes", typeref, size);
                }
                _ => {
                    println!(" Other type: {:?}", &type_info.datatype);
                }
            }
        }


    */

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.datatype {
            DbgDataType::Uint8 => f.write_str("Uint8"),
            DbgDataType::Uint16 => f.write_str("Uint16"),
            DbgDataType::Uint32 => f.write_str("Uint32"),
            DbgDataType::Uint64 => f.write_str("Uint64"),
            DbgDataType::Sint8 => f.write_str("Sint8"),
            DbgDataType::Sint16 => f.write_str("Sint16"),
            DbgDataType::Sint32 => f.write_str("Sint32"),
            DbgDataType::Sint64 => f.write_str("Sint64"),
            DbgDataType::Float => f.write_str("Float"),
            DbgDataType::Double => f.write_str("Double"),
            DbgDataType::Bitfield { .. } => f.write_str("Bitfield"),
            DbgDataType::Pointer(_, _) => write!(f, "Pointer(...)"),
            DbgDataType::Other(osize) => write!(f, "Other({osize})"),
            DbgDataType::FuncPtr(osize) => write!(f, "function pointer({osize})"),
            DbgDataType::Struct { members, is_class, .. } => {
                let kind = if *is_class { "Class" } else { "Struct" };
                if let Some(name) = &self.name {
                    write!(f, "{kind} {name}({} members)", members.len())
                } else {
                    write!(f, "{kind} <anonymous>({} members)", members.len())
                }
            }
            DbgDataType::Union { members, .. } => {
                if let Some(name) = &self.name {
                    write!(f, "Union {name}({} members)", members.len())
                } else {
                    write!(f, "Union <anonymous>({} members)", members.len())
                }
            }
            DbgDataType::Enum { enumerators, .. } => {
                if let Some(name) = &self.name {
                    write!(f, "Enum {name}({} enumerators)", enumerators.len())
                } else {
                    write!(f, "Enum <anonymous>({} enumerators)", enumerators.len())
                }
            }
            DbgDataType::Array { dim, arraytype, .. } => {
                write!(f, "Array({dim:?} x {arraytype})")
            }
            DbgDataType::TypeRef(t_ref, _) => write!(f, "TypeRef({t_ref})"),
        }
    }
}

#[cfg(test)]
mod test {}
