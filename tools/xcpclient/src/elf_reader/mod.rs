//--------------------------------------------------------------------------------------------------------------------------------------------------
// Module elf_reader
// Defines and implements ElfReader
// Read ELF files and extract debug information with DebugData (see copyright notice below)
// ElfReader provides functions to fill a XCP registry with events, segments, variables and metadata

// Based on Github repository a2ltool by DanielT: https://github.com/DanielT/a2ltool

/* 
Note on V2.1.10:
Updated to typereader.rs from a2ltool v3.4.1 (commit 0b61aa5, 2026-08-04).
The Class variant is gone. 
Struct now carries is_class and inheritance, and the size and Display code follow.
The two Class match arms from the previous fix are collapsed into the Struct arms, and a new test asserts that base members arrive for all four struct/class inheritance combinations.
*/






#![allow(clippy::collapsible_else_if)]

use indexmap::IndexMap;
use regex::Regex;
use std::error::Error;
use std::ffi::OsStr;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use xcp_registry::{McAddress, McDimType, McEvent, McIdentifier, McObjectQualifier, McObjectType, McSupportData, McValueType, Registry, RegistryError};

/*
Which information can be detected from ELF/DWARF:
    - Events:
        name, compilation unit, function name and CFA offset, but index is unknown
    - Memory segment name, type (naming convention name = reference page), address, length, but number is unknown
    - Variables:
        variable name, typename, absolute address, frame offset, compilation unit, function name, namespace
        static variables in functions get the correct event
        local variables on stack get the correct CFA
        name, type, compilation unit, namespace, location (register or stack)
    - Types:
        typedefs, structs, enums
        basic types: int8/16/32/64, uint8/16/32/64, float, double
        arrays 1D and 2D
        pointers (as ulong or ulonglong)

Key benefits:
    - Instance names get prefixed with function name if local stack or static variables
    - All instances get the correct fixed event id, if there is one in their scope, otherwise default event id is 0
    - Event compilation unit, function and CFA is detected to enable local variable access

Tools:
    dwarfdump --debug-info <filename>
    dwarfdump --debug-info --name <varname> <filename>
    objdump -h  <filename>
    objdump --syms <filename>

Limitations:
    - With -o1 most stack variables are in registers, have to be manually spilled to stack or captured
    - Segment numbers and event index are not constant expressions, need to be read by XCP (current solution) or from the binary persistence file from the target

Possible future improvements:
    - Thread load addressing mode
    - C++ support,  this addressing support, namespaces
    - Measurement of variables and function parameters in registers
    - Just in time compilation of variable access expressions
*/

// Dwarf reader
// This module contains modified code adapted from https://github.com/DanielT/a2ltool
// Original code licensed under MIT/Apache-2.0
// Copyright (c) DanielT
mod debuginfo;
use debuginfo::{DbgDataType, DebugData, TypeInfo, VarInfo};

//------------------------------------------------------------------------
//  ELF reader and A2L creator

pub(crate) struct ElfReader {
    pub(crate) debug_data: DebugData,
}

impl ElfReader {
    // Load debug information from the ELF file
    pub fn new(file_name: &str, verbose: usize, unit_idx_limit: usize) -> Option<ElfReader> {
        info!("Loading debug information from ELF file: {}", file_name);
        let debug_data = DebugData::load_dwarf(OsStr::new(file_name), verbose, unit_idx_limit);
        match debug_data {
            Ok(debug_data) => Some(ElfReader { debug_data }),
            Err(e) => {
                error!("Failed to load debug info from '{}': {}", file_name, e);
                None
            }
        }
    }

    // Get the McValueType for a given TypeInfo, which can be a basic type, pointer or array
    fn get_value_type(&self, reg: &mut Registry, type_info: &TypeInfo, object_type: McObjectType) -> McValueType {
        let type_size = type_info.get_size();
        match &type_info.datatype {
            DbgDataType::Uint8 => McValueType::Ubyte,
            DbgDataType::Uint16 => McValueType::Uword,
            DbgDataType::Uint32 => McValueType::Ulong,
            DbgDataType::Uint64 => McValueType::Ulonglong,
            DbgDataType::Sint8 => McValueType::Sbyte,
            DbgDataType::Sint16 => McValueType::Sword,
            DbgDataType::Sint32 => McValueType::Slong,
            DbgDataType::Sint64 => McValueType::Slonglong,
            DbgDataType::Float => McValueType::Float32Ieee,
            DbgDataType::Double => McValueType::Float64Ieee,
            DbgDataType::Struct { size, members, .. } => {
                if let Some(type_name) = self.debug_data.get_a2l_type_name(type_info) {
                    // Register a typedef for the struct/class type (no-op if it already exists).
                    // The identifier is sanitized once (e.g. "TplStruct<short unsigned int>" -> "TplStruct_short_unsigned_int_")
                    // and used for the typedef, its fields and the McValueType::TypeDef reference.
                    // Inherited members of structs and classes are already flattened into `members` by the DWARF reader.
                    let type_id = McIdentifier::from(type_name.to_string());
                    if let Err(e) = self.register_struct(reg, object_type, type_id, *size as usize, members) {
                        error!("Failed to register typedef '{}' for struct/class type '{}': {}", type_id, type_name, e);
                    }
                    McValueType::new_typedef(type_id)
                } else {
                    warn!("Struct/class type without name in get_value_type");
                    McValueType::Ubyte
                }
            }
            DbgDataType::Enum { size, signed, enumerators } => McValueType::from_integer_size(*size as usize, *signed),

            DbgDataType::TypeRef(typeref, size) => {
                if let Some(typeinfo) = self.debug_data.types.get(typeref) {
                    self.get_value_type(reg, typeinfo, object_type)
                } else {
                    error!("TypeRef {} to unknown in get_field_type", typeref);
                    McValueType::Ubyte
                }
            }

            DbgDataType::Pointer(size, _pointee) => {
                if *size == 4 {
                    McValueType::Ulong
                } else if *size == 8 {
                    McValueType::Ulonglong
                } else {
                    warn!("Unsupported pointer size {} in get_field_type", size);
                    McValueType::Ulonglong
                }
            }

            // These types are not a supported value type (arrays are handled in get_dim_type)
            // DbgDataType::Bitfield | DbgDataType::Union | DbgDataType::FuncPtr | DbgDataType::Other | DbgDataType::Array =>
            _ => {
                warn!("Unsupported type in get_field_type: {:?}", &type_info.datatype);
                //assert!(false, "Unsupported type in get_field_type: {:?}", &type_info.datatype);
                McValueType::Ubyte
            }
        }
    }

    // Get the dimension type for a variable, which is used to determine the number of elements and dimensions for arrays
    fn get_dim_type(&self, reg: &mut Registry, type_info: &TypeInfo, object_type: McObjectType) -> McDimType {
        let type_size = type_info.get_size();
        match &type_info.datatype {
            DbgDataType::Array { arraytype, dim, stride, size } => {
                assert!(dim.len() != 0);
                let elem_type = self.get_value_type(reg, arraytype, object_type);
                if dim.len() > 2 {
                    warn!("Only 1D and 2D arrays supported, got {}D", dim.len());
                    McDimType::new(McValueType::Ubyte, 1, 1)
                } else if dim.len() == 1 {
                    McDimType::new(elem_type, dim[0] as u16, 1)
                } else {
                    McDimType::new(elem_type, dim[0] as u16, dim[1] as u16)
                }
            }
            _ => McDimType::new(self.get_value_type(reg, type_info, object_type), 1, 1),
        }
    }

    // Register a struct/class type as typedef in the registry, including its members.
    // type_id is the sanitized identifier which is also used for the McValueType::TypeDef reference.
    // Ok(()) if the typedef was created or already exists (same type used by several variables or fields).
    fn register_struct(
        &self,
        reg: &mut Registry,
        object_type: McObjectType,
        type_id: McIdentifier,
        size: usize,
        members: &IndexMap<String, (TypeInfo, u64)>,
    ) -> Result<(), RegistryError> {
        match reg.add_typedef(type_id, size) {
            Ok(_) => {}
            Err(RegistryError::Duplicate(_)) => return Ok(()), // already registered, keep the existing definition
            Err(e) => return Err(e),
        }
        for (field_name, (type_info, field_offset)) in members {
            let Ok(offset) = u16::try_from(*field_offset) else {
                warn!("Field '{}.{}' skipped, offset {} exceeds the supported range", type_id, field_name, field_offset);
                continue;
            };
            let field_dim_type = self.get_dim_type(reg, type_info, object_type); // may recursively register nested typedefs
            reg.add_typedef_field(type_id.as_str(), field_name.clone(), field_dim_type, McSupportData::new(object_type), offset)?;
        }
        Ok(())
    }

    // Find the addressing mode marker variable (naming convention "XCPLITE__<signature>") and return the signature, if found
    // (CASDD, ACSDD, ...)
    pub fn get_target_signature(&self) -> Option<&str> {
        // Iterate over variables and look for XCPlite addressing mode marker
        for (var_name, var_infos) in &self.debug_data.variables {
            if !var_name.starts_with("XCPLITE__") {
                continue;
            }
            if let Some(signature) = var_name.strip_prefix("XCPLITE__") {
                return Some(signature);
            }
        }
        return None;
    }

    // Get the EPK string and address from debug_data and set it in the registry application version information, if available
    pub fn register_epk_addr_info(&self, reg: &mut Registry, verbose: usize) {
        info!("===============================================================");
        if self.debug_data.epk_addr > 0 {
            info!("EPK segment memory section found at address = 0x{:08X}", self.debug_data.epk_addr);
            let epk = self.debug_data.epk_string.clone().unwrap_or_else(|| "<unknown>".to_string());
            info!("EPK string: '{}'", epk);
            reg.application.set_version(epk, self.debug_data.epk_addr.try_into().unwrap());
        } else {
            warn!("EPK segment memory section not found in ELF file");
        }
    }

    // Register segments from segment creation markers (calseg__name) found in the code
    pub fn register_segments(&self, reg: &mut Registry, seg_relative: bool, verbose: usize) -> Result<(), Box<dyn Error>> {
        info!("===============================================================");
        info!(
            "Registering segment information {}:",
            if !seg_relative { "(absolute addressing mode)" } else { "(relative addressing mode)" }
        );

        // Step 1
        // Iterate over all variables and look for segment definition markers, which are created by the CalSegCreate or CalBlkCreate macros
        // Naming convention is "calseg__<name>" or "calblk__<name>"
        // Sort the vector by address to ensure the segments are processed in the order they are defined in the code
        // Index in the vector is now the segment number
        let mut seg_definitions: Vec<(String, &Vec<VarInfo>, u64, Option<u8>)> = Vec::new();
        for (var_name, var_infos) in &self.debug_data.variables {
            let is_calseg = var_name.starts_with("calseg__");
            let is_calblk = var_name.starts_with("calblk__");
            if is_calseg || is_calblk {
                let (seg_name, seg_number) = if is_calseg {
                    (var_name.strip_prefix("calseg__").unwrap_or(var_name), Some(0))
                } else {
                    (var_name.strip_prefix("calblk__").unwrap_or(var_name), None)
                };
                let mut seg_descr_addr = var_infos[0].address.1;
                if seg_name == "epk" {
                    // EPK segment is a special case, it has always index = 0
                    seg_descr_addr = 0;
                }
                assert!(var_infos.len() == 1);
                seg_definitions.push((seg_name.to_string(), var_infos, seg_descr_addr, seg_number));
            }
        }
        seg_definitions.sort_by_key(|x| x.2);
        // Calculate the segment numbers for calseg, calblk doues not have a number
        let mut seg_number: u8 = 0;
        for i in 0..seg_definitions.len() {
            if let Some(0) = seg_definitions[i].3 {
                seg_definitions[i].3 = Some(seg_number);
                seg_number += 1;
            }
        }

        // Print the found segment definition markers
        if verbose >= 1 {
            println!("Found {} segment definition marker variables:", seg_definitions.len());
            for (seg_index, (var_name, var_infos, var_address, seg_number)) in seg_definitions.iter().enumerate() {
                println!("{}: '{}' - number={:?}, addr={:08X}'", seg_index, var_name, seg_number, var_address);
                if verbose >= 2 {
                    let var_info = &var_infos[0];
                    let function_name = if let Some(f) = var_info.function.as_ref() { f.as_str() } else { "" };
                    let unit_idx = var_info.unit_idx;
                    let unit_name = if let Some(name) = self.debug_data.make_simple_unit_name(unit_idx) {
                        name
                    } else {
                        format!("{unit_idx}")
                    };
                    println!("  found in {}:'{}'", unit_name, function_name);
                }
            }
        }

        // Step 2
        // Iterate over the segment definitions and register the segments in the registry
        for (seg_index, (seg_name, var_infos, var_address, seg_number)) in seg_definitions.iter().enumerate() {
            let var_info = &var_infos[0];
            let seg_length: u16;
            let seg_addr: u64;

            // Special case for EPK segment, which does not have a reference page variable, but the segment address and length may be stored in the debug data from the EPK section
            if seg_name == "epk" {
                if let Some(epk_str) = self.debug_data.epk_string.as_ref() {
                    seg_length = epk_str.len().try_into().expect("EPK string length exceeds 64K");
                    seg_addr = self.debug_data.epk_addr;
                } else {
                    error!("No EPK segment memory section in ELF file, segment '{}' skipped", seg_name);
                    continue; // skip this variable
                }
            }
            // Not epk segment
            else {
                // Lookup the reference page variable (by naming convention: same as segment name!) information
                // This may be ambigous, so we use some heuristics to select the right variable
                // @@@@ TODO use the commandline compilation unit filter here
                let seg_var_info = if let Some(x) = self.debug_data.variables.get(seg_name) {
                    let mut valid_candidates: Vec<_> = x.iter().filter(|var_info| var_info.address.0 == 0 && var_info.address.1 != 0).collect();
                    if valid_candidates.len() > 1 {
                        let same_unit_candidates: Vec<_> = valid_candidates.iter().copied().filter(|candidate| candidate.unit_idx == var_info.unit_idx).collect();
                        if same_unit_candidates.len() == 1 {
                            valid_candidates = same_unit_candidates;
                        }
                    }
                    if valid_candidates.len() != 1 {
                        error!(
                            "Calibration segment reference page variable '{}' has {} usable definitions, expected 1 ({} total DWARF entries)",
                            seg_name,
                            valid_candidates.len(),
                            x.len()
                        );
                        if verbose >= 1 {
                            for candidate in x {
                                let unit_name = self.debug_data.make_simple_unit_name(candidate.unit_idx).unwrap_or_else(|| candidate.unit_idx.to_string());
                                let function_name = candidate.function.as_deref().unwrap_or("<global>");
                                println!(
                                    "  candidate in {}:'{}', addr_class={}, addr=0x{:08X}",
                                    unit_name, function_name, candidate.address.0, candidate.address.1
                                );
                            }
                        }
                        continue;
                    }
                    valid_candidates[0]
                } else {
                    error!("Could not find calibration segment reference page variable '{}'", seg_name);
                    continue;
                };

                // Determine segment length
                seg_length = {
                    if let Some(type_info) = self.debug_data.types.get(&seg_var_info.typeref) {
                        println!(
                            "Calibration segment '{}' type information found, type={}, size = {}",
                            seg_name,
                            type_info.name.as_ref().map_or("<unnamed>", |s| s.as_str()),
                            type_info.get_size()
                        );
                        if verbose >= 2 {
                            println!("  type = {}", type_info);
                        }
                        type_info.get_size().try_into().expect("segment size exceeds 64K")
                    } else {
                        error!("Could not determine length type for segment {}", seg_name);
                        0
                    }
                };

                // Determine segment address
                // @@@@ TODO: handle signed relative encoding
                seg_addr = seg_var_info.address.1;
                if !(seg_length > 0 && seg_addr > 0 && seg_var_info.address.0 == 0) {
                    error!(
                        "Calibration segment from cal_<name> '{}' not found, has invalid address {:#x} or size {:#x}, skipped",
                        seg_name, seg_addr, seg_length
                    );
                    continue; // skip this variable
                }

                info!(
                    "Calibration segment '{}' default page variable found in debug data: Address = {:#x}, Size = {:#x}",
                    seg_name, seg_addr, seg_length
                );
            } // not EPK segment

            // Find the segment by name in the registry
            if let Some(reg_seg) = reg.cal_seg_list.find_cal_seg(seg_name) {
                info!("Calibration segment '{}' {}:0x{:08X} found in registry", seg_name, reg_seg.addr_ext, reg_seg.addr);
                // Segment relative addressing mode
                if reg_seg.addr == 0x80000000 + ((reg_seg.index as u32) << 16) {
                    info!("  with segment relative addressing");
                    // Check if length matches
                    if reg_seg.size == seg_length as u32 {
                        reg_seg.set_mem_addr(seg_addr);
                        info!("  matches existing registry entry");
                    } else {
                        warn!("Calibration segment '{}' length does not match existing registry entry", seg_name);
                    }
                }
                // Segment absolute addressing mode
                else {
                    // Check if address and length match
                    if reg_seg.addr as u64 != seg_addr {
                        warn!(
                            "Calibration segment '{}' address does not match existing registry entry, reg = {:08X} vs. {:08X}",
                            seg_name, reg_seg.addr, seg_addr
                        );
                    } else if reg_seg.size != seg_length as u32 {
                        warn!(
                            "Calibration segment '{}' length does not match existing registry entry, reg = {} vs. {}",
                            seg_name, reg_seg.size, seg_length
                        );
                    } else {
                        info!("Calibration segment '{}' matches existing registry entry", seg_name);
                    }
                } // absolute addressing mode
            }
            // already existing
            //
            // If not existing, create the segment
            // Use segment relative or absolute addressing mode
            else {
                info!("Calibration segment '{}' not yet defined in registry", seg_name);

                if seg_relative {
                    // Add in segment relative addressing mode
                    let res = reg.cal_seg_list.add_cal_seg(seg_name.to_string(), *seg_number, seg_length as u32);
                    if let Err(e) = res {
                        error!("Failed to add calibration segment '{}': {}", seg_name, e);
                        continue;
                    }
                } else {
                    // Absolute addressing mode
                    if seg_addr >= 0xFFFFFFFF {
                        error!(
                            "Calibration segment '{}' has 64 bit address {:#x}, which does not fit the 32 bit XCP address range",
                            seg_name, seg_addr
                        );
                        continue; // skip 
                    }
                    if seg_index >= 255 {
                        error!("Too many calibration segments, segment index {} does not fit in u8 for segment '{}'", seg_index, seg_name);
                        continue; // skip
                    }
                    if seg_length == 0 {
                        error!("Calibration segment '{}' has zero length, skipped", seg_name);
                        continue; // skip
                    }
                    let res = reg
                        .cal_seg_list
                        .add_cal_seg_by_addr(seg_name.to_string(), *seg_number, 0, seg_addr as u32, seg_length as u32);
                    if let Err(e) = res {
                        error!("Failed to add calibration segment '{}': {}", seg_name, e);
                        continue;
                    }
                }

                // Set memory address for later lookup of potential calibration variables in this segment
                let new_seg = reg.cal_seg_list.find_cal_seg(seg_name).unwrap();
                new_seg.set_mem_addr(seg_addr);

                info!(
                    "Created segment {}: '{}':  addr = 0x{:08X}, size = {}, mem_addr = 0x{:08X}",
                    seg_index, seg_name, new_seg.addr, new_seg.size, new_seg.mem_addr
                );
            } // not already existing
        } // for
        Ok(())
    }

    // Register events from event creation markers (evt__name) in the code
    pub fn register_events(&self, reg: &mut Registry, verbose: usize) -> Result<(), Box<dyn Error>> {
        info!("===============================================================");

        info!("Registering event information:");

        // Get the address range of the XCP event descriptor memory section (start is 0 if not found)
        let xcp_event_section_addr = self.debug_data.get_event_section_addr();
        let xcp_event_section_end = self
            .debug_data
            .sections
            .get("xcp_evts")
            .map(|(_, end)| *end)
            .or_else(|| self.debug_data.symbol_addresses.get("__stop_xcp_evts").copied());

        // Placeholder ids for events whose id can not be determined from the event descriptor section
        // They must be unique in the registry, counting down from 0xFFFF keeps them out of the range of real event ids
        // The ids are corrected from the XCP server event information when connected (see --fix-a2l)
        let mut next_undefined_event_id: u16 = 0xFFFF;

        // Location "unit:function" of a marker variable for messages
        let location = |v: &VarInfo| -> String {
            let unit_name = self.debug_data.make_simple_unit_name(v.unit_idx).unwrap_or_else(|| v.unit_idx.to_string());
            format!("{}:{}", unit_name, v.function.as_deref().unwrap_or(""))
        };

        // Iterate over variables
        for (var_name, var_infos) in &self.debug_data.variables {
            // Skip standard library variables and system/compiler internals (__<name>)s
            // Skip global XCP variables (gXCP.. and gA2L..)
            if var_name.starts_with("__") || var_name.starts_with("gXcp") || var_name.starts_with("gA2l") {
                continue;
            }

            // Event definitions (by markers from DaqCreateEvent macro)
            // (thread local) static evt__<name>, name is event name
            if let Some(evt_name) = var_name.strip_prefix("evt__") {
                let Some(first) = var_infos.first() else {
                    continue;
                };

                // The DaqCreateEvent macro emits one event descriptor per call site. If the same event is created in several
                // functions or compilation units, the target creates the event once for the first descriptor in the section
                // (XcpInit scans the section in address order), so the definition with the lowest address is used here as well
                let var_info = var_infos.iter().filter(|v| v.address.1 != 0).min_by_key(|v| v.address.1).unwrap_or(first);
                info!(
                    "Event definition for event '{}' found in {}, addr = {:#x}",
                    evt_name,
                    location(var_info),
                    var_info.address.1
                );
                if var_infos.len() > 1 {
                    let others: Vec<String> = var_infos.iter().filter(|v| !std::ptr::eq(*v, var_info)).map(|v| location(v)).collect();
                    warn!(
                        "Event '{}' is defined {} times, using the definition in {} (also defined in {})",
                        evt_name,
                        var_infos.len(),
                        location(var_info),
                        others.join(", ")
                    );
                }

                // Skip if the event already exists in the registry (e.g. from the XCP server event information)
                if reg.event_list.find_event(evt_name, 0).is_some() {
                    continue;
                }

                // Determine the event id from the position of the event descriptor in the event descriptor section
                let addr = var_info.address.1;
                let mut event_id: Option<u16> = None;
                if xcp_event_section_addr > 0 && addr >= xcp_event_section_addr && xcp_event_section_end.is_none_or(|end| addr < end) {
                    let id = ((addr - xcp_event_section_addr) / 16) as u16; // @@@@ size of tXcpEventDescriptor hardcoded
                    if let Some(other) = reg.event_list.find_event_id(id) {
                        warn!("Event id {} of event '{}' is already used by event '{}'", id, evt_name, other.get_name());
                    } else {
                        event_id = Some(id);
                    }
                } else if xcp_event_section_addr > 0 {
                    warn!("Event definition marker of event '{}' at {:#x} is outside the event descriptor section", evt_name, addr);
                }

                match event_id {
                    Some(id) => {
                        reg.event_list.add_event(McEvent::new(evt_name.to_string(), 0, id, 0))?;
                        info!("New event '{}' found: event id = {}", evt_name, id);
                    }
                    None => {
                        // Use a unique placeholder id, it has to be corrected later from the XCP server event information
                        let mut id = next_undefined_event_id;
                        while reg.event_list.find_event_id(id).is_some() {
                            id = id.saturating_sub(1);
                        }
                        next_undefined_event_id = id.saturating_sub(1);
                        reg.event_list.add_event(McEvent::new(evt_name.to_string(), 0, id, 0))?;
                        warn!(
                            "New event '{}' found, created with undefined event id {:#06x}, correct it with the XCP server event information",
                            evt_name, id
                        );
                    }
                }
            }
        }
        Ok(())
    }

    // Find event triggers in the code and register their location (compilation unit, function, CFA offset)
    pub fn register_event_locations(&self, reg: &mut Registry, verbose: usize) -> Result<(), Box<dyn Error>> {
        info!("===============================================================");

        info!("Registering event locations:");

        // Iterate over variables
        for (var_name, var_infos) in &self.debug_data.variables {
            // Skip standard library variables and system/compiler internals (__<name>)s
            // Skip global XCP variables (gXCP.. and gA2L..)
            if var_name.starts_with("__") || var_name.starts_with("gXcp") || var_name.starts_with("gA2l") {
                continue;
            }

            // trg__<event_name> (thread local static, name is event name)
            // Event definitions (thread local static variables)
            if var_name.starts_with("trg__") {
                // One trigger location per event is expected, the location is used to resolve stack relative variables
                if var_infos.len() > 1 {
                    warn!(
                        "Event trigger marker '{}' is defined {} times, only the first definition is used to locate stack variables",
                        var_name,
                        var_infos.len()
                    );
                }
                let Some(var_info) = var_infos.first() else {
                    continue;
                };

                // Get the event name from format  "trg__<tag>__<eventname>" prefix
                let s = var_name.strip_prefix("trg__").unwrap_or("unnamed");
                let mut parts = s.split("__");
                let evt_mode = parts.next().unwrap_or("");
                let evt_name = parts.next().unwrap_or("");

                let evt_unit_idx = var_infos[0].unit_idx;
                let evt_unit_name = if let Some(name) = self.debug_data.make_simple_unit_name(evt_unit_idx) {
                    name
                } else {
                    format!("{evt_unit_idx}")
                };
                let evt_function = if let Some(f) = var_info.function.as_ref() { f.as_str() } else { "" };
                info!(
                    "  Event {} trigger found in {}:{}, address resolver mode {}",
                    evt_name, evt_unit_name, evt_function, evt_mode
                );

                // Find the event in the registry
                if let Some(_evt) = reg.event_list.find_event(evt_name, 0) {
                    // Try to lookup the canonical stack frame address offset from the function name
                    let mut evt_cfa: i32 = 0;
                    for cfa_info in self.debug_data.cfa_info.iter() {
                        if cfa_info.unit_idx == evt_unit_idx && cfa_info.function == evt_function {
                            if let Some(x) = cfa_info.cfa_offset {
                                evt_cfa = x as i32;
                            } else {
                                warn!("Could not determine CFA offset for function '{}'", evt_function);
                            }
                            break;
                        }
                    }

                    if verbose >= 1 {
                        println!("  Event '{}' trigger in function '{}', cfa = {}", evt_name, evt_function, evt_cfa);
                    }

                    // Store the unit and function name and canonical stack frame address offset for this event trigger
                    match reg.event_list.set_event_location(evt_name, evt_unit_idx, evt_function, evt_cfa) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Failed to set event location for event '{}': {}", evt_name, e);
                        }
                    }
                } else {
                    error!("Event '{}' for trigger not found in registry", evt_name);
                }
                continue; // skip this variable
            }
        }
        Ok(())
    }

    pub fn register_variables(
        &self,
        reg: &mut Registry,
        seg_relative: bool,
        verbose: usize,
        unit_idx_limit: usize,
        name_filter: &str,
        unit_filter: &str,
    ) -> Result<(), Box<dyn Error>> {
        // Load debug information from the ELF file
        info!("===============================================================");
        info!("Registering variables:");

        // Compile name filter regex if specified
        let name_regex: Option<Regex> = if name_filter.is_empty() {
            None
        } else {
            match Regex::new(name_filter) {
                Ok(re) => {
                    info!("Variable name filter: '{}'", name_filter);
                    Some(re)
                }
                Err(e) => {
                    return Err(format!("Invalid --elf-var-filter regex '{}': {}", name_filter, e).into());
                }
            }
        };

        // Compile compilation unit filter regex if specified
        let unit_regex: Option<Regex> = if unit_filter.is_empty() {
            None
        } else {
            match Regex::new(unit_filter) {
                Ok(re) => {
                    info!("Compilation unit filter: '{}'", unit_filter);
                    Some(re)
                }
                Err(e) => {
                    return Err(format!("Invalid --elf-unit-filter regex '{}': {}", unit_filter, e).into());
                }
            }
        };

        // Iterate over variables
        for (var_name, var_infos) in &self.debug_data.variables {
            // Skip standard library variables and system/compiler internals (__<name>)s
            // Skip global XCP variables (gXCP.. and gA2L..) and special marker variables (calseg__, evt__, trg__, xcp_meta__)
            if var_name.starts_with("__")
                || var_name.starts_with("gXcp")
                || var_name.starts_with("gA2l")
                || var_name.starts_with("calseg__")
                || var_name.starts_with("calblk__")
                || var_name.starts_with("evt__")
                || var_name.starts_with("trg__")
                || var_name.starts_with("xcp_meta__")
            {
                continue;
            }

            // Apply name filter
            if let Some(ref re) = name_regex {
                if !re.is_match(var_name) {
                    continue;
                }
            }

            if var_infos.is_empty() {
                warn!("Variable '{}' has no variable info", var_name);
            }

            let mut a2l_name = var_name.to_string();
            let mut xcp_event_id = 0; // default event id is 0, async event in transmit thread

            // daq__<event_name>__<var_name> (local scope static variables)
            // Check for captured variables with format "daq__<event_name>__<var_name>"
            if var_name.starts_with("daq__") {
                // remove the "daq__" prefix
                let new_name = var_name.strip_prefix("daq__").unwrap_or(var_name);
                // get event name and variable name
                let mut parts = new_name.split("__");
                let event_name = parts.next().unwrap_or("");
                let var_name = parts.next().unwrap_or("");
                // Find the event in the registry
                if let Some(id) = reg.event_list.find_event(event_name, 0) {
                    xcp_event_id = id.id;
                    if event_name.len() > 0 {
                        a2l_name = format!("{}.{}", event_name, var_name);
                    } else {
                        a2l_name = var_name.to_string();
                    }
                } else {
                    warn!("Event '{}' for captured variable '{}' not found in registry", event_name, var_name);
                    continue; // skip this variable
                }
            }

            // Count variables with this name in compilation unit 0
            let count = var_infos.iter().filter(|v| v.unit_idx <= unit_idx_limit).count();

            // Process all variable with this name in different scopes and namespaces
            for var_info in var_infos {
                // @@@@ TODO: Create only variables from specified compilation unit
                if var_info.unit_idx > unit_idx_limit {
                    continue;
                }

                // Apply compilation unit filter
                if let Some(ref re) = unit_regex {
                    let cu_name = self.debug_data.make_simple_unit_name(var_info.unit_idx).unwrap_or_else(|| format!("{}", var_info.unit_idx));
                    if !re.is_match(&cu_name) {
                        continue;
                    }
                }

                let var_function = if let Some(f) = var_info.function.as_ref() { f.as_str() } else { "" };

                // Address encoder
                let mem_addr_ext: u8 = var_info.address.0;
                let mem_addr: u64 = if mem_addr_ext == 0 {
                    // Encode absolute addressing mode
                    if var_info.address.1 == 0 {
                        debug!("Variable '{}' in function '{}' skipped, no address", var_name, var_function);
                        continue; // skip this variable
                    } else if var_info.address.1 >= 0xFFFFFFFF {
                        warn!(
                            "Variable '{}' skipped, has 64 bit address {:#x}, which does not fit the 32 bit XCP address range",
                            var_name, var_info.address.1
                        );
                        continue; // skip this variable
                    } else {
                        // find an event triggered in this function
                        if let Some(event) = reg.event_list.find_event_by_location(var_info.unit_idx, var_function) {
                            xcp_event_id = event.id;
                            info!("Variable '{}' is local to function '{}', using event id = {}", var_name, var_function, xcp_event_id);
                        } else {
                            debug!("Variable '{}' is local to function '{}', but no event found", var_name, var_function);
                        }
                        // multiple variables with this name, prefix with function name
                        if count > 1 {
                            if var_function.len() > 0 {
                                a2l_name = format!("{}.{}", var_function, var_name);
                            } else {
                                a2l_name = var_name.to_string();
                            }
                        }
                        var_info.address.1
                    }
                }
                // Encode relative addressing mode
                else if mem_addr_ext == 2 {
                    // Find an event id for this local variable
                    if let Some(event) = reg.event_list.find_event_by_location(var_info.unit_idx, var_function) {
                        // Set the event id for this function
                        // Prefix the variable with the function name
                        xcp_event_id = event.id;
                        let cfa: i64 = event.cfa as i64;
                        if var_function.len() > 0 {
                            a2l_name = format!("{}.{}", var_function, var_name);
                        } else {
                            a2l_name = var_name.to_string();
                        }
                        debug!(
                            "Variable '{}' is local to function '{}', using event id = {}, dwarf_offset = {} cfa = {}",
                            var_name,
                            var_function,
                            xcp_event_id,
                            (var_info.address.1 as i64 - 0x80000000) as i64,
                            cfa
                        );

                        // @@@@ TODO: Create functions instead of constants for relative address encoding
                        // Encode dyn addressing mode A2L/XCP address from offset and event id
                        let offset: i64 = var_info.address.1 as i64 - 0x80000000 + cfa;
                        if offset < -(McAddress::XCP_ADDR_EXT_DYN_OFFSET_OFFSET as i64)
                            || offset > (McAddress::XCP_ADDR_EXT_DYN_OFFSET_MASK as i64 - McAddress::XCP_ADDR_EXT_DYN_OFFSET_OFFSET as i64)
                        {
                            warn!(
                                "Variable '{}' skipped, has offset {} which does not fit the XCP dynamic addressing mode range",
                                var_name, offset
                            );
                            continue; // skip this variable
                        }

                        (((offset + McAddress::XCP_ADDR_EXT_DYN_OFFSET_OFFSET as i64) as u64) & McAddress::XCP_ADDR_EXT_DYN_OFFSET_MASK as u64)
                            | ((event.id as u64) << McAddress::XCP_ADDR_EXT_DYN_OFFSET_BITS)
                    } else {
                        debug!("Variable '{}' skipped, could not find event for dyn addressing mode", var_name);
                        continue; // skip this variable
                    }
                }
                // @@@@ TODO: Handle other address extensions
                else {
                    debug!("Variable '{}' skipped, has unsupported address extension {:#x}", var_name, mem_addr_ext);
                    continue; // skip this variable
                };

                // Check if the absolute address is in a calibration segment or block
                // For segments with segment relative and absolute addressing mode, we always need to check with the memory address of the segment, not the a2l address
                let seg_name = reg.cal_seg_list.find_cal_seg_by_mem_address(mem_addr);
                let (object_type, mc_addr) = if let Some(seg_name) = seg_name {
                    let seg = reg.cal_seg_list.find_cal_seg(&seg_name).unwrap();
                    let offset: u16 = (mem_addr - seg.mem_addr).try_into().unwrap();
                    // Address extension of characteristics in memory segments is always 0, hardcoded here
                    // @@@@ NOTE: This might change in the future
                    (McObjectType::Characteristic, McAddress::new_a2l(seg.addr + offset as u32, 0))
                } else {
                    // Create a McAddress with event id, mem_addr is relative or absolute
                    // @@@@ TODO: Not implemented dependency on target addressing scheme
                    // Address extension might be 0, 1, 2 depending on the target addressing scheme
                    let addr_ext = if seg_relative && mem_addr_ext == 0 {
                        1 // set to absolute addressing mode
                    } else {
                        mem_addr_ext
                    };
                    (McObjectType::Measurement, McAddress::new_a2l_with_event(xcp_event_id, mem_addr as u32, addr_ext))
                };

                // Register measurement variable if possible
                if let Some(type_info) = self.debug_data.types.get(&var_info.typeref) {
                    // Register supported variable types in the registry
                    let type_size = type_info.get_size();
                    let type_name = &type_info.name;
                    match &type_info.datatype {
                        DbgDataType::Uint8
                        | DbgDataType::Uint16
                        | DbgDataType::Uint32
                        | DbgDataType::Uint64
                        | DbgDataType::Sint8
                        | DbgDataType::Sint16
                        | DbgDataType::Sint32
                        | DbgDataType::Sint64
                        | DbgDataType::Float
                        | DbgDataType::Double
                        | DbgDataType::Array { .. }
                        | DbgDataType::Struct { .. } => {
                            if verbose >= 2 {
                                print!(
                                    "  Add {} instance for {}: addr = {}:0x{:08x}",
                                    if object_type == McObjectType::Characteristic { "characteristic" } else { "measurement" },
                                    a2l_name,
                                    mem_addr_ext,
                                    mem_addr
                                );
                                if verbose >= 3 {
                                    println!(" type = {}", type_info);
                                } else {
                                    println!();
                                }
                            }
                            let dim_type = self.get_dim_type(reg, type_info, object_type);
                            let res = reg.instance_list.add_instance(a2l_name.clone(), dim_type, McSupportData::new(object_type), mc_addr);
                            match res {
                                Ok(_) => {
                                    if verbose >= 1 {
                                        println!(
                                            "Registered variable '{}' type_name = '{}', size = {}, event_id = {}",
                                            a2l_name,
                                            type_name.as_ref().unwrap_or(&"<unnamed>".to_string()),
                                            type_size,
                                            xcp_event_id
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to register variable '{}': {}", a2l_name, e);
                                }
                            }
                        }
                        // Special case for enum types, which are represented as integer types with enumerators described as special unit format "value "NAME" value "NAME" ...".
                        // We convert the enumerators to a unit string and store it in the McSupportData for the instance.
                        DbgDataType::Enum { size, signed, enumerators } => {
                            if verbose >= 2 {
                                print!(
                                    "  Add {} instance for enum {}: addr = {}:0x{:08x}, size = {}, signed = {}, enumerators = {:?}",
                                    if object_type == McObjectType::Characteristic { "characteristic" } else { "measurement" },
                                    a2l_name,
                                    mem_addr_ext,
                                    mem_addr,
                                    size,
                                    signed,
                                    enumerators
                                );
                                if verbose >= 3 {
                                    println!(" type = {}", type_info);
                                } else {
                                    println!();
                                }
                            }
                            let dim_type = self.get_dim_type(reg, type_info, object_type);
                            let unit_string = enumerators_to_unit_string(enumerators);
                            let mc_support_data = if let Some(unit_str) = unit_string {
                                McSupportData::new(object_type).set_unit(unit_str)
                            } else {
                                warn!("Enum variable '{}' has no enumerators, no conversion table generated", a2l_name);
                                McSupportData::new(object_type)
                            };
                            let res = reg.instance_list.add_instance(a2l_name.clone(), dim_type, mc_support_data, mc_addr);
                            match res {
                                Ok(_) => {
                                    if verbose >= 1 {
                                        println!(
                                            "Registered enum variable '{}' with type '{}', size = {}, event id = {}, unit = {:?}",
                                            a2l_name,
                                            type_name.as_ref().unwrap_or(&"<unnamed>".to_string()),
                                            type_size,
                                            xcp_event_id,
                                            enumerators_to_unit_string(enumerators)
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to register variable '{}': {}", a2l_name, e);
                                }
                            }
                        }

                        _ => {
                            warn!("Variable '{}' has unsupported type: {}", var_name, type_info);
                        }
                    }
                } else {
                    warn!("TypeRef {} of variable '{}' not found in debug info", var_info.typeref, var_name);
                }
            }
        } // var_infos
        Ok(())
    }

    /// Read XCP_UNIT / XCP_LIMITS / XCP_COMMENT metadata from the xcp_meta ELF section
    /// and apply them to already-registered instances in the registry.
    /// Must be called after register_variables.
    pub fn register_metadata(&self, reg: &mut Registry, verbose: usize) -> Result<(), Box<dyn Error>> {
        info!("===============================================================");
        info!("Registering metadata from xcp_meta section:");

        // Get meta_base_addr and meta_end
        let (meta_base_addr, meta_data) = match &self.debug_data.xcp_meta_data {
            Some(data) => data,
            None => {
                info!("No xcp_meta section found, skipping metadata registration");
                return Ok(());
            }
        };
        let meta_end = meta_base_addr + meta_data.len() as u64;
        let is_le = self.debug_data.is_little_endian;
        assert!(is_le, "Big endian is not supported for meta data registration");

        // Search for metadata variables (xcp_meta__<kind>__<base_name>) in the debug data
        // Add meta data to the registry instances
        for (var_name, var_infos) in &self.debug_data.variables {
            // Only process metadata variables
            let Some(rest) = var_name.strip_prefix("xcp_meta__") else {
                continue;
            };
            let Some((kind, base_name)) = rest.split_once("__") else {
                warn!("Unexpected xcp_meta__ variable name format: '{}'", var_name);
                continue;
            };
            if var_infos.is_empty() {
                continue;
            }

            // Get the address and section offset of the metadata variable
            let var_addr = var_infos[0].address.1;
            if var_addr == 0 {
                warn!("Metadata variable '{}' address is 0", var_name);
                continue;
            }
            if var_addr < *meta_base_addr || var_addr >= meta_end {
                warn!("Metadata variable '{}' address 0x{:08X} is outside xcp_meta section", var_name, var_addr);
                continue;
            }
            let offset = (var_addr - meta_base_addr) as usize;

            // Decode base_name: __ is the path separator, e.g. "params__delay_us" means
            // instance "params", field "delay_us".  Replace all __ with . to get the dot path.
            let dot_path = base_name.replace("__", ".");

            // Path A — typedef field metadata (instance + dot-separated field path)
            // Applies when base_name contains __, i.e. it encodes a struct field reference.
            // Uses set_instance_field_support_data which walks the typedef tree.
            let field_applied = if dot_path.contains('.') {
                let (instance_name, field_path) = dot_path.split_once('.').unwrap();
                apply_field_metadata(reg, var_name, kind, instance_name, field_path, meta_data, offset, is_le, verbose)
            } else {
                false
            };

            // Path B — direct instance metadata (simple variable or flattened typedef)
            // Matches instances whose A2L name equals dot_path or ends with ".{dot_path}".
            // dot_path already has . separators so it matches both "delay_us" and "params.delay_us".
            let escaped = dot_path.replace('.', "\\.");
            let pattern = format!(r"^(.*\.)?{}$", escaped);
            let names: Vec<String> = reg.instance_list.find_instances_regex(&pattern, McObjectType::Unspecified, None);
            for name in &names {
                if let Some(inst) = reg.instance_list.get_instance_mut(name, None) {
                    apply_instance_metadata(inst, kind, meta_data, offset, is_le);
                    if verbose >= 1 {
                        println!("  Metadata {} {} applied to instance '{}'", kind, var_name, name);
                    }
                }
            }

            if !field_applied && names.is_empty() {
                warn!("Metadata '{}': no matching registry entry for '{}'", var_name, dot_path);
            }
        }

        Ok(())
    }
}

// Convert an enumerators vec to the XCP/A2L COMPU_VTAB string format: `value "NAME" value "NAME" ...`
fn enumerators_to_unit_string(enumerators: &[(String, i64)]) -> Option<String> {
    if enumerators.is_empty() {
        return None;
    }
    let parts: Vec<String> = enumerators.iter().map(|(name, value)| format!(r#"{} "{}""#, value, name)).collect();
    Some(parts.join(" "))
}

// Read a null-terminated UTF-8 string from a byte slice at a given offset
fn read_cstr_at(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..].iter().position(|&b| b == 0).map(|p| offset + p).unwrap_or(data.len());
    String::from_utf8(data[offset..end].to_vec()).ok()
}

// Path A helper: apply metadata to a typedef field via set_instance_field_support_data.
// Returns true if the metadata was successfully applied.
fn apply_field_metadata(
    reg: &mut Registry,
    var_name: &str,
    kind: &str,
    instance_name: &str,
    field_path: &str,
    meta_data: &[u8],
    offset: usize,
    is_le: bool,
    verbose: usize,
) -> bool {
    let support_data = match kind {
        "unit" | "comment" => {
            let Some(value) = read_cstr_at(meta_data, offset) else {
                warn!("Failed to read string for metadata variable '{}'", var_name);
                return false;
            };
            let sd = McSupportData::new(McObjectType::Unspecified);
            if kind == "unit" { sd.set_unit(value) } else { sd.set_comment(value) }
        }
        "min" | "max" => {
            if offset + 8 > meta_data.len() {
                warn!("Not enough bytes for f64 at offset {} in xcp_meta for '{}'", offset, var_name);
                return false;
            }
            let bytes: [u8; 8] = meta_data[offset..offset + 8].try_into().unwrap();
            let value = if is_le { f64::from_le_bytes(bytes) } else { f64::from_be_bytes(bytes) };
            let sd = McSupportData::new(McObjectType::Unspecified);
            if kind == "min" { sd.set_min(Some(value)) } else { sd.set_max(Some(value)) }
        }
        "read_write" => {
            let sd = McSupportData::new(McObjectType::Unspecified);
            sd.set_read_write()
        }
        _ => {
            warn!("Unknown metadata kind '{}' in variable '{}'", kind, var_name);
            return false;
        }
    };

    match reg.set_instance_field_support_data(instance_name, field_path, support_data) {
        Ok(()) => {
            if verbose >= 1 {
                println!("  Metadata {} applied to typedef field '{}.{}'", var_name, instance_name, field_path);
            }
            true
        }
        Err(RegistryError::NotFound(_)) => false, // no such instance or field — not an error, Path B will try
        Err(e) => {
            warn!("Metadata '{}': set_instance_field_support_data failed: {}", var_name, e);
            false
        }
    }
}

// Path B helper: apply metadata directly to an McInstance's mc_support_data.
fn apply_instance_metadata(inst: &mut xcp_registry::McInstance, kind: &str, meta_data: &[u8], offset: usize, is_le: bool) {
    match kind {
        "read_write" => {
            inst.mc_support_data.update_qualifier(McObjectQualifier::ReadWrite);
        }
        "unit" | "comment" => {
            if let Some(value) = read_cstr_at(meta_data, offset) {
                if kind == "unit" {
                    inst.mc_support_data.update_unit(value);
                } else {
                    inst.mc_support_data.update_comment(value);
                }
            }
        }
        "min" | "max" => {
            if offset + 8 <= meta_data.len() {
                let bytes: [u8; 8] = meta_data[offset..offset + 8].try_into().unwrap();
                let value = if is_le { f64::from_le_bytes(bytes) } else { f64::from_be_bytes(bytes) };
                if kind == "min" {
                    inst.mc_support_data.update_min(Some(value));
                } else {
                    inst.mc_support_data.update_max(Some(value));
                }
            }
        }
        _ => {}
    }
}

//------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod test {
    use super::*;

    // C++ type test fixture, see fixtures/cpp_types.cpp (GCC 12.3 arm-none-eabi, DWARF 5)
    const CPP_TYPES_ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/cpp_types.elf");
    // C++ type-name collision fixture, see fixtures/cpp_type_name_collisions.cpp
    const CPP_TYPE_NAME_COLLISIONS_ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/cpp_type_name_collisions.elf");

    fn load_cpp_types() -> Registry {
        let elf_reader = ElfReader::new(CPP_TYPES_ELF, 0, usize::MAX).expect("failed to load fixtures/cpp_types.elf");
        let mut reg = Registry::new();
        elf_reader.register_variables(&mut reg, false, 0, usize::MAX, "", "").expect("register_variables failed");
        reg
    }

    // Variables and struct members of C++ class type are registered like structs
    #[test]
    fn test_register_class_types() {
        let reg = load_cpp_types();

        for (var_name, typedef_name) in [
            ("g_pubclass", "PubClass"),
            ("g_tpl_class", "TplClass_long_unsigned_int_"),
            ("g_derived_cc", "DerivedCC"),
            ("g_derived_cs", "DerivedCS"),
            ("g_derived_ss", "DerivedSS"),
            ("g_derived_sc", "DerivedSC"),
        ] {
            let inst = reg
                .instance_list
                .get_instance(var_name, McObjectType::Measurement, None)
                .unwrap_or_else(|| panic!("instance '{var_name}' not registered"));
            assert_eq!(inst.dim_type.value_type, McValueType::new_typedef(typedef_name), "{var_name}");
        }

        let pub_class = reg.typedef_list.find_typedef("PubClass").expect("typedef PubClass");
        assert_eq!(pub_class.size, 8);
        assert_eq!(pub_class.find_field("x").map(|f| f.offset), Some(0));
        assert_eq!(pub_class.find_field("y").map(|f| f.offset), Some(4));

        // Inherited members of a class derived from a class are flattened by the DWARF reader
        let derived_cc = reg.typedef_list.find_typedef("DerivedCC").expect("typedef DerivedCC");
        assert_eq!(derived_cc.find_field("cbase_a").map(|f| f.offset), Some(0));
        assert_eq!(derived_cc.find_field("cderived_b").map(|f| f.offset), Some(4));

        // A class typed struct member references the class typedef instead of degrading to UBYTE
        let outer = reg.typedef_list.find_typedef("Outer").expect("typedef Outer");
        let inner_class = outer.find_field("inner_class").expect("field Outer.inner_class");
        assert_eq!(inner_class.dim_type.value_type, McValueType::new_typedef("PubClass"));
        assert_eq!(inner_class.offset, 0);
    }

    // Base class members are flattened into the derived type for all struct/class combinations
    #[test]
    fn test_register_inherited_members() {
        let reg = load_cpp_types();

        for (typedef_name, base_member, derived_member) in [
            ("DerivedSS", "base_a", "derived_b"),
            ("DerivedCC", "cbase_a", "cderived_b"),
            ("DerivedCS", "base_a", "cs_b"),
            ("DerivedSC", "cbase_a", "sc_b"),
        ] {
            let typedef = reg
                .typedef_list
                .find_typedef(typedef_name)
                .unwrap_or_else(|| panic!("typedef '{typedef_name}' not registered"));
            assert_eq!(typedef.size, 8, "{typedef_name}");
            assert_eq!(typedef.fields.len(), 2, "{typedef_name} member count");
            assert_eq!(typedef.find_field(base_member).map(|f| f.offset), Some(0), "{typedef_name}.{base_member}");
            assert_eq!(typedef.find_field(derived_member).map(|f| f.offset), Some(4), "{typedef_name}.{derived_member}");
        }
    }

    // Typedef names which are sanitized (template instantiations) get their members and a matching reference
    #[test]
    fn test_register_template_struct_members() {
        let reg = load_cpp_types();

        for typedef_name in ["TplStruct_short_unsigned_int_", "TplStruct_float_", "TplClass_long_unsigned_int_"] {
            let typedef = reg
                .typedef_list
                .find_typedef(typedef_name)
                .unwrap_or_else(|| panic!("typedef '{typedef_name}' not registered"));
            assert_eq!(typedef.size, 8, "{typedef_name}");
            assert_eq!(typedef.fields.len(), 2, "{typedef_name} has no members");
            assert_eq!(typedef.find_field("value").map(|f| f.offset), Some(0), "{typedef_name}.value");
            assert_eq!(typedef.find_field("count").map(|f| f.offset), Some(4), "{typedef_name}.count");
        }

        let outer = reg.typedef_list.find_typedef("Outer").unwrap();
        let inner_tpl = outer.find_field("inner_tpl").expect("field Outer.inner_tpl");
        assert_eq!(inner_tpl.dim_type.value_type, McValueType::new_typedef("TplStruct_short_unsigned_int_"));
        assert_eq!(inner_tpl.offset, 8);
    }

    // Identically named types in different namespaces get distinct typedefs and matching instance references
    #[test]
    fn test_register_namespaced_types_with_colliding_names() {
        let elf_reader = ElfReader::new(CPP_TYPE_NAME_COLLISIONS_ELF, 0, usize::MAX)
            .expect("failed to load fixtures/cpp_type_name_collisions.elf");
        let mut reg = Registry::new();
        elf_reader.register_variables(&mut reg, false, 0, usize::MAX, "", "").expect("register_variables failed");

        for (instance_name, expected_type_name) in [
            ("g_namespace_1_type_a", "namespace_1.TypeA"),
            ("g_namespace_2_type_a", "namespace_2.TypeA"),
            ("g_namespace_1_type_b", "namespace_1.TypeB"),
            ("g_namespace_2_type_b", "namespace_2.TypeB"),
        ] {
            let instance = reg
                .instance_list
                .get_instance(instance_name, McObjectType::Measurement, None)
                .unwrap_or_else(|| panic!("instance '{instance_name}' not registered"));
            assert_eq!(instance.dim_type.value_type, McValueType::new_typedef(expected_type_name), "{instance_name}");
        }

        assert_eq!(reg.typedef_list.len(), 4);
        assert!(reg.typedef_list.find_typedef("namespace_1.TypeA").unwrap().find_field("member_1").is_some());
        assert!(reg.typedef_list.find_typedef("namespace_2.TypeA").unwrap().find_field("member_2").is_some());
        assert!(reg.typedef_list.find_typedef("namespace_1.TypeB").unwrap().find_field("member_2").is_some());
        assert!(reg.typedef_list.find_typedef("namespace_2.TypeB").unwrap().find_field("member_3").is_some());
    }

    // Build an ElfReader from hand-made debug data containing only event definition (evt__) and trigger (trg__) marker variables
    fn elf_reader_with_markers(markers: &[(&str, u64, &str)], event_section: Option<(u64, u64)>) -> ElfReader {
        use std::collections::HashMap;
        let mut variables: IndexMap<String, Vec<VarInfo>> = IndexMap::new();
        for (name, addr, function) in markers {
            variables.entry(name.to_string()).or_default().push(VarInfo {
                address: (0, *addr),
                typeref: 0,
                unit_idx: 0,
                function: Some(function.to_string()),
                namespaces: Vec::new(),
            });
        }
        let mut sections = HashMap::new();
        if let Some(range) = event_section {
            sections.insert("xcp_evts".to_string(), range);
        }
        ElfReader {
            debug_data: DebugData {
                variables,
                types: HashMap::new(),
                typenames: HashMap::new(),
                a2l_type_names: HashMap::new(),
                demangled_names: HashMap::new(),
                unit_names: vec![Some("main.c".to_string())],
                sections,
                symbol_addresses: HashMap::new(),
                cfa_info: Vec::new(),
                epk_string: None,
                epk_addr: 0,
                xcp_meta_data: None,
                is_little_endian: true,
            },
        }
    }

    // An event created in several functions has several definition markers, the first descriptor in the section wins,
    // duplicate trigger markers must not panic either
    #[test]
    fn test_register_events_duplicate_definitions() {
        let elf = elf_reader_with_markers(
            &[
                ("evt__foo", 0x1010, "task_b"),
                ("evt__foo", 0x1000, "task_a"),
                ("evt__bar", 0x1020, "main"),
                ("trg__AAS__foo", 0x2000, "task_a"),
                ("trg__AAS__foo", 0x2004, "task_b"),
            ],
            Some((0x1000, 0x1030)),
        );
        let mut reg = Registry::new();
        elf.register_events(&mut reg, 0).unwrap();
        assert_eq!(reg.event_list.find_event("foo", 0).unwrap().get_id(), 0);
        assert_eq!(reg.event_list.find_event("bar", 0).unwrap().get_id(), 2);
        assert!(reg.event_list.find_event_id(1).is_none());
        elf.register_event_locations(&mut reg, 0).unwrap();
        assert!(reg.event_list.find_event_by_location(0, "task_a").is_some());
    }

    // Without an event descriptor section every event gets a unique placeholder id (previously all got 0xFFFF and the second one panicked)
    #[test]
    fn test_register_events_without_descriptor_section() {
        let elf = elf_reader_with_markers(&[("evt__foo", 0x1000, "main"), ("evt__bar", 0x1010, "main"), ("evt__baz", 0, "main")], None);
        let mut reg = Registry::new();
        elf.register_events(&mut reg, 0).unwrap();
        let ids: Vec<u16> = ["foo", "bar", "baz"].iter().map(|n| reg.event_list.find_event(n, 0).unwrap().get_id()).collect();
        assert_eq!(ids, vec![0xFFFF, 0xFFFE, 0xFFFD]);
    }

    // Markers outside the descriptor section, without address or with an id which is already taken get placeholder ids
    #[test]
    fn test_register_events_marker_outside_section() {
        let elf = elf_reader_with_markers(
            &[("evt__foo", 0x1000, "main"), ("evt__out", 0x5000, "main"), ("evt__zero", 0, "main")],
            Some((0x1000, 0x1010)),
        );
        let mut reg = Registry::new();
        reg.event_list.add_event(McEvent::new("srv", 0, 0, 0)).unwrap(); // id 0 is taken, e.g. by the XCP server event information
        elf.register_events(&mut reg, 0).unwrap();
        assert_eq!(reg.event_list.find_event("foo", 0).unwrap().get_id(), 0xFFFF);
        assert_eq!(reg.event_list.find_event("out", 0).unwrap().get_id(), 0xFFFE);
        assert_eq!(reg.event_list.find_event("zero", 0).unwrap().get_id(), 0xFFFD);
    }
}
