# xcpclient

XCP test client implementation in Rust

Used for integration testing and for uploading or generating A2L files.  
Partial XCP implementation with hard-coded protocol settings for XCPlite.  

## How offline A2L generation works

xcpclient generates A2L files from ELF/DWARF debug information written into the firmware by
the XCPlite instrumentation macros — no runtime A2L code is needed in the application.

**Three sources of information** are combined:

1. **`xcp_evts` ELF section** — the XCPlite macros (`DaqCreateEvent`, `DaqCreateAndTriggerEvent`)
   emit a `tXcpEventDescriptor` constant per event into this named section. xcpclient iterates
   it to discover every event defined in the firmware, including name, cycle time, and priority.

2. **`xcp_cals` ELF section** — `CalSegDecl` emits a `tXcpCalSegDescriptor` constant per
   calibration segment into this section, containing the segment name, address of the default
   page, and its size. xcpclient uses this to discover all calibration segments.

3. **DWARF debug info** — every trigger macro also emits a named static variable (e.g.
   `trg__AAS__eventname`) whose DWARF lexical scope covers the same local variables as the
   trigger point. xcpclient walks the DWARF to find these anchor variables, reads the
   addressing mode from their name, and associates all in-scope local variables with the
   corresponding event as measurements.

**Preconditions in the application code:**
- Use the XCPlite macros (`DaqCreateEvent`, `DaqTriggerEvent`, `CalSegDecl`, …),
  never the raw C API — only macros emit the ELF markers.
- Build with debug info (`-g` / `Debug` or `RelWithDebInfo`).
- Mark local measurement variables `volatile` so the compiler keeps them on the stack frame
  and DWARF location expressions remain valid in optimized builds.

For the full technical specification — ELF section layouts, the `trg__` anchor naming
convention, and the `AddrExt` encoding — see
[docs/TECHNICAL.md — Offline A2L Generation](../../docs/TECHNICAL.md#offline-a2l-generation--elfdwarf-internals).

### Supported types and known limitations

The DWARF type information is mapped to A2L objects as follows:

| C/C++ type | A2L representation |
|---|---|
| `bool`, integer and floating point types | `MEASUREMENT` or `CHARACTERISTIC` of the matching A2L data type |
| `enum` | integer of the enum's size; for variables the enumerators become a verbal conversion table, enum struct members are plain integers |
| one- and two-dimensional arrays | `MEASUREMENT` / `CHARACTERISTIC` with `MATRIX_DIM` (`VAL_BLK`, `CURVE`, `MAP`); arrays of structs become arrays of typedef instances |
| `struct`, `class`, template instantiations | `TYPEDEF_STRUCTURE` + `INSTANCE`; nested structs and classes become nested typedefs; private members are included; base class members are flattened into the derived type for all combinations of `struct`/`class` bases; `static`/`constexpr` members are skipped |
| pointers as struct or class members | the address value as unsigned integer of the target's pointer size, the pointee is not followed |

Type names which are not valid A2L identifiers (template instantiations such as `TplStruct<float>`) are sanitized to `TplStruct_float_`.
Colliding C++ type names are qualified with their namespace or enclosing type (for example, `namespace_1.TypeA`).
The `TYPEDEF_MEASUREMENT`/`TYPEDEF_CHARACTERISTIC` of a struct field is named after the field; if another structure has a field with
the same name but a different type or metadata, the name is qualified with the structure name (`TplStruct_float_.value`).

Not supported, skipped and reported as warnings (log level 2 and above):

- Variables of pointer type (measure the pointed-to variable instead).
- Unions, bitfields and function pointers. A struct member of such a type is written as a one byte `UBYTE` placeholder
  so that the remaining members of the structure keep their offsets.
- Arrays with more than two dimensions (written as a one byte placeholder).
- C++ pointer-to-member types (`DW_TAG_ptr_to_member_type`): a struct or class containing one cannot be read at all,
  so it and every class deriving from it end up without members. This is a limitation of the a2ltool DWARF reader
  this code is based on.
- C++ library containers (`std::vector`, `std::string`, smart pointers, ...) are read as the structs they are;
  the heap data behind them is not reachable.




XCP client v2.1.x for testing XCP servers and managing A2L and HEX files.

This tool can:
- Connect to XCP on Ethernet servers via TCP or UDP and show information about the XCP protocol and the target ECU
- Upload A2L or ELF files from XCP servers (GET_ID command)
- Create A2L files from ELF/DWARF debug information including event and memory segment information obtained from the XCP server or from an ELF file
- Create A2L file templates for from a XCPlite ELF/DWARF
- Fix A2L files with event and memory segment information from the XCP server
- Read and write calibration variables (CAL)
- Upload (from target) and download (to target) binary files (Intel-HEX) with calibration segment data
- List available measurement variables and parameters with regex patterns
- Test data acquisition (DAQ)
- Execute test sequences


Usage: xcpclient [OPTIONS]

Options:
      --log-level <LOG_LEVEL>
          Log level (Off=0, Error=1, Warn=2, Info=3, Debug=4, Trace=5) [default: 3]

      --verbose <VERBOSE>
          Verbose output Enables additional output when reading ELF files and creating A2L files
            
      --dest-addr <DEST_ADDR>
          XCP server address (IP address or IP:port). If port is omitted, uses --port parameter [default: 127.0.0.1]

      --port <PORT>
          XCP server port number (used when --dest-addr doesn't include port) [default: 5555]

      --bind-addr <BIND_ADDR>
          Bind address (IP address or IP:port). If port is omitted, system assigns an available port [default: 0.0.0.0]

      --tcp
          Use TCP for XCP communication..

      --udp
          Use UDP for XCP communication

      --connect-mode <CONNECT_MODE>
          XCP connect mode

      --offline
          Force offline mode (no network communication), communication parameters are used to create A2L file

      --a2l <A2L>
          Specify and overide the name of the A2L file name. If not specified, The A2L file name is read from the XCP server
          
      --upload-a2l
          Upload A2L file from XCP server. Requires that the XCP server supports GET_ID A2L upload

      --create-a2l
          Build an A2L file template from XCP server information about events and memory segments. Requires that the XCP server supports the GET_EVENT_INFO and GET_SEGMENT_INFO commands. Insert all visible measurement and calibration variables from ELF file if specified with --elf or --upload-elf

      --create-a2l-template
          Build a minimal A2L template from XCP server event and memory segment information only. No variables or types are registered; the result is a skeleton A2L file. Requires that the XCP server supports the GET_EVENT_INFO and GET_SEGMENT_INFO commands

      --fix-a2l
          Update the given A2L file with XCP server information about events and memory segments. Requires that the XCP server supports the GET_EVENT_INFO and GET_SEGMENT_INFO commands

      --upload-elf
          Upload ELF file from XCP server. Requires that the XCP server supports proprietary GET_ID ELF upload command

      --elf <ELF>
          Specify the name of an ELF file, create an A2L file from ELF debug information. If connected to a XCP server, events and memory segments will be extracted from the XCP server

      --elf-unit-limit <ELF_UNIT_LIMIT>
          Parse only compilations units <= n

      --elf-var-filter <ELF_VAR_FILTER>
          Regex pattern to filter variable names when registering from an ELF file.
          Only variables whose names match the pattern are included in the A2L output.
          If not specified (or empty), all variables are registered.
          Example: --elf-var-filter "counter.*"

      --elf-unit-filter <ELF_UNIT_FILTER>
          Regex pattern to filter variables by their compilation unit (source file) name.
          Only variables defined in compilation units whose name matches are included in the A2L output.
          If not specified (or empty), variables from all compilation units are registered.
          Example: --elf-cu-filter "my_module.*"

      --bin <BIN>
          Specify the pathname of a binary file (Intel-HEX) for calibration parameter segment data

      --upload-bin
          Upload all calibration segments working page data from target and store into a binary file. Requires that the XCP server supports GET_ID A2L upload

      --download-bin
          Download all calibration segments working page data in a binary file to the target

      --list-mea <LIST_MEA>
          Lists all specified measurement variables (regex) found in the A2L file

      --mea <MEA>...
          Specify variable names for DAQ measurement (list), may be list of names separated by space or single regular expressions (e.g. ".*")

      --time <TIME>
          Time limit measurement duration to n s. 0 means infinite

      --csv <CSV>
          Save measurement data to a CSV file. If not specified, data is printed to the console. CSV format: time_ns,daq,name,value  (one row per measurement sample)

      --list-cal <LIST_CAL>
          Lists all specified calibration variables (regex) found in the A2L file
          
      --cal <NAME> <VALUE>
          Set calibration variable to a value (format: "variable_name value")

      --test
          --test Execute a test sequence on the XCP server

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version


## Build and Install

```bash
cd tools/xcpclient
cargo install --path . --locked
```

## Test

```bash
cd tools/xcpclient
cargo test
```


## Examples

### List all calibration or measurement variables

```bash
xcpclient --dest-addr 192.168.0.206 --udp --list-cal .
xcpclient --dest-addr 192.168.0.206 --udp --list-mea .
```

### Set a calibration variable

Set variable counter_max to 1000
```bash
xcpclient --dest-addr 192.168.0.206 --port 5555 --tcp --cal counter_max 1000
```

### Measure variables

Measure everything from uploaded A2L file for 5 seconds with detailed log to terminal:  

```bash
xcpclient --dest-addr=127.0.0.1  --udp --upload-a2l --mea ".*" --time 5 --verbose 2
```

With A2L file given:  

```bash
xcpclient --dest-addr=192.168.0.206  --tcp --a2l hello_xcp.a2l  --mea ".*" 
```

With ELF file given, creates an A2L file from the ELF file and XCP server information about events and memory segments, then measures the specified variable:  

```bash
xcpclient --udp --elf build/hello_xcp --mea "counter" --verbose 2
```


### Upload the A2L file to be used from the target

```bash
xcpclient --dest-addr=192.168.0.206:5555 --tcp --upload-a2l   
```

### Create an A2L file for a target from ELF without on target A2L generation support

Ccreate an A2L file from the ELF file (and optional XCP server information about events and memory segments), then save the A2L file as hello_xcp.a2l:
```bash

# offline
xcpclient --offline --elf examples/no_a2l_demo/CANape/no_a2l_demo.elf --a2l examples/no_a2l_demo/CANape/no_a2l_demo_template.a2l --create-a2l-template 
xcpclient --offline --elf examples/no_a2l_demo/CANape/no_a2l_demo.elf --a2l examples/no_a2l_demo/CANape/no_a2l_demo.a2l --create-a2l

# online with XCP server information about events and memory segments
xcpclient --dest-addr=192.168.0.206:5555 --udp  --create-a2l --elf no_a2l_demo.elf --a2l no_a2l_demo.a2l 
```

Upload the ELF file into hello_xcp.elf and create an A2L file from the ELF file and XCP server information about events and memory segments, then save the A2L file as hello_xcp.a2l:
```bash
xcpclient --dest-addr=192.168.0.206:5555 --udp --create-a2l --upload-elf --elf hello_xcp.elf --a2l hello_xcp.a2l 
```

### Upload an Intel-HEX file with the current calibration data

```bash
xcpclient --upload-bin test.hex
```


#### Demo

```bash

# A2l from no_a2l_demo.out
cargo r --  --elf no_a2l_demo.out --elf-unit-limit 1000 --log-level 3  --create-a2l --a2l no_a2l_demo.a2l   --offline  


cargo r --  --dest-addr 192.168.0.206 --udp --elf no_a2l_demo.out --elf-unit-limit 1000 --log-level 3  --create-a2l --a2l no_a2l_demo.a2l 

cargo r --  --dest-addr 192.168.0.206  --elf no_a2l_demo.out --elf-unit-limit 1000 --log-level 3  --create-a2l --a2l no_a2l_demo.a2l --list-mea 'counter'

cargo r --  --dest-addr 192.168.0.206  --elf no_a2l_demo.out --elf-unit-limit 1000 --log-level 3  --create-a2l --a2l no_a2l_demo.a2l --mea 'counter'  --time 5 --verbose 2

```
