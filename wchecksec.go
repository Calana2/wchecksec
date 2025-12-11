package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

const (
	DLLC_HighEntropyVirtualAddressSpace = 0x32
	DLLC_DynamicBase                    = 0x40
	DLLC_ForceIntegrity                 = 0x80
	DLLC_NXCompatible                   = 0x100
	DLLC_NoIsolation                    = 0x200
	DLLC_NoSeh                          = 0x400
	DLLC_ControlFlowGuard               = 0x4000
)

const (
	WIN_CERT_TYPE_X509             = 0x0001
	WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002 // Authenticode
	WIN_CERT_TYPE_RESERVD_1        = 0x0003
	WIN_CERT_TYPE_TS_STACK_SIGNED  = 0x0004
)

const (
	PE32 = iota
	PE64
)

// Global
var f *os.File
var pe int8
var e_lfanew uint32
var IMAGE_BASE uint64
var numberOfRvaAndSizes uint32
var numberOfSections uint16
var sectionHeaders []*IMAGE_SECTION_HEADER

var PE32_IMAGE_MAGIC = []byte{0x0b, 0x01}
var PE64_IMAGE_MAGIC = []byte{0x0b, 0x02}

type IMAGE_SECTION_HEADER struct {
	Name             string
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	// omit the rest of the fields...
}

type ENTRY_LOAD_CONFIG_DIRECTORY struct {
	Size                    uint32
	TimeDateStamp           uint32
	MajorVersion            uint16
	MinorVersion            uint16
	GlobalFlagsClear        uint32
	GlobalFlagsSet          uint32
	CriticalSectionTimeout  uint32
	DeCommitFreeThreshold   uint64 // PE32/PE64 dependent
	DeCommitTotalThreshold  uint64 // PE32/PE64 dependent
	LockPrefixTable         uint64 // PE32/PE64 dependent
	MaximumAllocationSize   uint64 // PE32/PE64 dependent
	VirtualMemoryThreshold  uint64 // PE32/PE64 dependent
	ProcessHeapFlags        uint64 // PE32/PE64 dependent
	ProcessAffinityMask     uint32
	CSDVersion              uint16
	Reserved1               uint16
	EditList                uint64 // PE32/PE64 dependent
	SecurityCookie          uint64 // PE32/PE64 dependent
	SEHandlerTable          uint64 // PE32/PE64 dependent
	SEHandlerCount          uint64 // PE32/PE64 dependent
	GuardCFCheckFunction    uint64 // PE32/PE64 dependent
	GuardCFDispatchFunction uint64 // PE32/PE64 dependent
	GuardCFFunctionTable    uint64 // PE32/PE64 dependent
	GuardCFFunctionCount    uint64 // PE32/PE64 dependent
	GuardFlags              uint32
}

func u64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }
func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func u16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }

func parseSectionHeaders(f *os.File, IMAGE_SECTION_BASE uint32) []*IMAGE_SECTION_HEADER {
	var headers []*IMAGE_SECTION_HEADER
	f.Seek(int64(IMAGE_SECTION_BASE), 0)
	buffer := make([]byte, numberOfSections*0x28)
	f.Read(buffer)
	for i := 0; i < int(numberOfSections); i++ {
		base := 0x28 * i
		sh := &IMAGE_SECTION_HEADER{}
		sh.Name = string(buffer[base : base+8])
		sh.VirtualSize = u32(buffer[base+8 : base+12])
		sh.VirtualAddress = u32(buffer[base+12 : base+16])
		sh.SizeOfRawData = u32(buffer[base+16 : base+20])
		sh.PointerToRawData = u32(buffer[base+20 : base+24])
		headers = append(headers, sh)
	}
	return headers
}

func parseLoadConfigDirectory(f *os.File, ENTRY_LOAD_CONFIG_ADDRESS uint32, is64 bool) *ENTRY_LOAD_CONFIG_DIRECTORY {
	lcd := &ENTRY_LOAD_CONFIG_DIRECTORY{SEHandlerTable: 0, SEHandlerCount: 0, SecurityCookie: 0}
	if ENTRY_LOAD_CONFIG_ADDRESS == 0 {
		return lcd
	}
	f.Seek(int64(ENTRY_LOAD_CONFIG_ADDRESS), 0)
	buf := make([]byte, 0x100)
	f.Read(buf)
	off := 0

	lcd.Size = u32(buf[off : off+4])
	off += 4
	lcd.TimeDateStamp = u32(buf[off : off+4])
	off += 4
	lcd.MajorVersion = u16(buf[off : off+2])
	off += 2
	lcd.MinorVersion = u16(buf[off : off+2])
	off += 2
	lcd.GlobalFlagsClear = u32(buf[off : off+4])
	off += 4
	lcd.GlobalFlagsSet = u32(buf[off : off+4])
	off += 4
	lcd.CriticalSectionTimeout = u32(buf[off : off+4])
	off += 4
	lcd.DeCommitFreeThreshold = readUintPtr(buf, &off, is64)
	lcd.DeCommitTotalThreshold = readUintPtr(buf, &off, is64)
	lcd.LockPrefixTable = readUintPtr(buf, &off, is64)
	lcd.MaximumAllocationSize = readUintPtr(buf, &off, is64)
	lcd.VirtualMemoryThreshold = readUintPtr(buf, &off, is64)

	lcd.ProcessHeapFlags = readUintPtr(buf, &off, is64)
	lcd.ProcessAffinityMask = u32(buf[off : off+4])
	off += 4
	lcd.CSDVersion = u16(buf[off : off+2])
	off += 2
	lcd.Reserved1 = u16(buf[off : off+2])
	off += 2

	lcd.EditList = readUintPtr(buf, &off, is64)
	lcd.SecurityCookie = readUintPtr(buf, &off, is64)
	lcd.SEHandlerTable = readUintPtr(buf, &off, is64)
	lcd.SEHandlerCount = readUintPtr(buf, &off, is64)
	lcd.GuardCFCheckFunction = readUintPtr(buf, &off, is64)
	lcd.GuardCFDispatchFunction = readUintPtr(buf, &off, is64)
	lcd.GuardCFFunctionTable = readUintPtr(buf, &off, is64)
	lcd.GuardCFFunctionCount = readUintPtr(buf, &off, is64)
	lcd.GuardFlags = u32(buf[off : off+4])
	return lcd
}

func pad(def string, msg string) string {
	return fmt.Sprintf("%-20s%s\n", def+":", msg)
}

func readUintPtr(data []byte, off *int, is64 bool) uint64 {
	if is64 {
		val := u64(data[*off : *off+8])
		*off += 8
		return val
	}
	val := uint64(u32(data[*off : *off+4]))
	*off += 4
	return val
}

func rvaToOffset(rva uint32, sections []*IMAGE_SECTION_HEADER) uint32 {
	for _, sec := range sections {
		start := sec.VirtualAddress
		end := start + sec.SizeOfRawData
		if rva >= start && rva < end {
			return (rva - start) + sec.PointerToRawData
		}
	}
	return 0
}

// This is for pattern match assembly instructions in GS search
func MatchPattern(data, pattern, mask []byte) bool {
	match := func(data, pattern, mask []byte) bool {
		if len(data) < len(pattern) {
			return false
		}
		for i := 0; i < len(pattern); i++ {
			if mask[i] == 0xFF && data[i] != pattern[i] {
				return false
			}
		}
		return true
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		if match(data[i:], pattern, mask) {
			return true
		}
	}
	return false
}

func parseDLLCharacteristics(f *os.File, v uint16) string {
	var buffer []byte
	var info string
	var hasASLR bool = true
	var IMAGE_SECTION_HEADER_BASE int
	if pe == PE32 {
		IMAGE_SECTION_HEADER_BASE = int(e_lfanew + 0x18 + numberOfRvaAndSizes*8 + 0x60)
	} else {
		IMAGE_SECTION_HEADER_BASE = int(e_lfanew + 0x18 + numberOfRvaAndSizes*8 + 0x70)
	}
	sectionHeaders = parseSectionHeaders(f, uint32(IMAGE_SECTION_HEADER_BASE))

	// ** ASLR (Address Space Layout Randomization)**
	if v&DLLC_DynamicBase != 0 {
		hasReloc := false
		for _, section := range sectionHeaders {
			if strings.Contains(section.Name, ".reloc") {
				hasReloc = true
				break
			}
		}
		// no relocs!
		if !hasReloc {
			hasASLR = false
			info += pad("ASLR", "Disabled (No Relocations)")
		} else {
			// high entropy
			if v&DLLC_HighEntropyVirtualAddressSpace != 0 {
				info += pad("ASLR", "Enabled  (High Entropy)")
			} else {
				// base
				info += pad("ASLR", "Enabled")
			}
		}
	} else {
		hasASLR = false
		info += pad("ASLR", "Disabled")
	}

	// Print OPTIONAL_HEADER.IMAGE_BASE
	if !hasASLR {
		info += fmt.Sprintf("%-20s0x%x\n", "Image Base:", IMAGE_BASE)
	}

	// ** DEP (Data Execution Prevention) **
	if v&DLLC_NXCompatible != 0 {
		info += pad("DEP", "Enabled")
	} else {
		info += pad("DEP", "Disabled")
	}

	// ** CFG (Control Flow Guard) **
	if v&DLLC_ControlFlowGuard != 0 {
		info += pad("CFG", "Enabled")
	} else {
		info += pad("CFG", "Disabled")
	}

	// find IMAGE_DATA_DIRECTORY[] LOAD_CONFIG
	buffer = make([]byte, 4)
	if pe == PE32 {
		f.Seek(int64(e_lfanew+0x18+0x60+0xa*8), 0)
	} else {
		f.Seek(int64(e_lfanew+0x18+0x70+0xa*8), 0)
	}
	f.Read(buffer)
	ENTRY_LOAD_CONFIG_RVA := u32(buffer)
	ENTRY_LOAD_CONFIG_ADDRESS := rvaToOffset(ENTRY_LOAD_CONFIG_RVA, sectionHeaders)
	ConfigDirectory := parseLoadConfigDirectory(f, ENTRY_LOAD_CONFIG_ADDRESS, pe == PE64)

	// ** SafeSEH (Safe Structured Exception Handler) **
	if pe == PE64 {
		info += pad("SafeSEH", "Disabled (not available for 64-bit binaries)")
	} else if v&DLLC_NoSeh != 0 {
		info += pad("SafeSEH", "Disabled")
	} else {
		if ENTRY_LOAD_CONFIG_ADDRESS == 0 {
			info += pad("SafeSEH", "Disabled (missing ENTRY_LOAD_CONFIG directory)")
		} else {
			if ConfigDirectory.SEHandlerTable == 0 {
				info += pad("SafeSEH", "Disabled (missing SEHandlerTable)")
			} else {
				info += pad("SafeSEH", "Enabled")
			}
		}
	}

	// ** GS (Buffer security check) **
	if ENTRY_LOAD_CONFIG_ADDRESS == 0 || ConfigDirectory.SecurityCookie == 0 {

		// -- Extract .text section
		var textSection *IMAGE_SECTION_HEADER
		for _, section := range sectionHeaders {
			if strings.Contains(section.Name, ".text") {
				textSection = section
				break
			}
		}

		if isDotNETDirectory(f, int64(e_lfanew)) {
			info += pad("GS", "Disabled")
		} else if textSection != nil && textSection.SizeOfRawData != 0 {
			// Try heuristic search based on MSVC compiler instructions
			textData := make([]byte, textSection.SizeOfRawData)
			f.Seek(int64(textSection.PointerToRawData), 0)
			f.Read(textData)
			// -- Select pattern
			var scc_init_pattern []byte
			var scc_init_mask []byte
			var scc_call_pattern []byte
			var scc_call_mask []byte
			if pe == PE64 {
				scc_init_pattern = []byte{
					0x48, 0x83, 0xec, 0x00, // SUB RSP, imm8
					0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, // MOV RAX,QWORD PTR [RSP + imm32]
					0x48, 0x33, 0xc4, // XOR RAX, RSP
					0x48, 0x89, 0x44, 0x24, 0x00, // mov QWORD PTR [RSP + imm8],rax
				}
				scc_init_mask = []byte{
					0xff, 0xff, 0xff, 0x00,
					0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
					0xff, 0xff, 0xff,
					0xff, 0xff, 0xff, 0xff, 0x00,
				}
				scc_call_pattern = []byte{
					0x33, 0xc0, // XOR EAX, EAX
					0x48, 0x8b, 0x4c, 0x24, 0x00, // MOV RCX, [RSP + imm8]
					0x48, 0x33, 0xcc, // XOR RCX, RSP
					0xe8, 0x00, 0x00, 0x00, 0x00, // CALL rel32
					0x48, 0x83, 0xc4, 0x00, // ADD RSP, imm8 (I guess a LEAVE instruction will work here too)
					0xc3, // RET
				}
				scc_call_mask = []byte{
					0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0x00,
					0xFF, 0xFF, 0xFF,
					0xFF, 0x00, 0x00, 0x00, 0x00,
					0xFF, 0xFF, 0xFF, 0x00,
					0xFF,
				}
			} else {
				scc_init_pattern = []byte{
					0x48, 0x83, 0xec, 0x00, // SUB ESP, imm8
					0x81, 0xec, 0x00, 0x00, 0x00, 0x00, // MOV EAX, ds:imm32
					0x33, 0xc4, // XOR EAX, ESP
					0x89, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, // MOV DWORD PTR [ESP + imm32], EAX
				}
				scc_init_mask = []byte{
					0xff, 0xff, 0xff, 0x00,
					0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
					0xff, 0xff,
					0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				}
				scc_call_pattern = []byte{
					0x33, 0xcc, // XOR ECX, ESP
					0xe8, 0x00, 0x00, 0x00, 0x00, // CALL rel32
					0x8b, 0xe5, // MOV ESP, EBP
					0x5d, // POP EBP
					0xc3, // RET
				}
				scc_call_mask = []byte{
					0xFF, 0xFF,
					0xFF, 0x00, 0x00, 0x00, 0x00,
					0xFF, 0xFF,
					0xFF,
					0xFF,
				}
			}
			if MatchPattern(textData, scc_init_pattern, scc_init_mask) &&
				MatchPattern(textData, scc_call_pattern, scc_call_mask) {
				info += pad("GS", "Enabled  (heuristic pattern match)")
			} else {
				info += pad("GS", "Disabled")
			}
		} // !isDotNet branch end
	} else if ConfigDirectory.SecurityCookie != 0 {
		// ConfigDirectory.SecurityCookie is a VA
		SecurityCookieRVA := uint32(ConfigDirectory.SecurityCookie - IMAGE_BASE)
		f.Seek(int64(rvaToOffset(SecurityCookieRVA, sectionHeaders)), 0)
		buffer := make([]byte, 8)
		f.Read(buffer)
		if pe == PE64 {
			info += pad("GS", fmt.Sprintf("Enabled  (stack_cookie=0x%x)", u64(buffer)))
		} else {
			info += pad("GS", fmt.Sprintf("Enabled  (stack_cookie=0x%x)", u32(buffer[:4])))
		}
	}

	// ** Isolation **
	if v&DLLC_NoIsolation != 0 {
		info += pad("Isolation", "Disabled")
	} else {
		info += pad("Isolation", "Enabled")
	}

	// ** Force Integrity **
	if v&DLLC_ForceIntegrity != 0 {
		info += pad("Force Integrity", "Enabled")
	} else {
		info += pad("Force Integrity", "Disabled")
	}

	// find IMAGE_DATA_DIRECTORY[] SECURITY
	buffer = make([]byte, 8)
	if pe == PE32 {
		f.Seek(int64(e_lfanew+0x18+0x60+0x4*8), 0)
	} else {
		f.Seek(int64(e_lfanew+0x18+0x70+0x4*8), 0)
	}
	f.Read(buffer)

	// ** Authenticode **
	WIN_CERT_ADDRESS := u32(buffer[:4])
	WIN_CERT_SIZE := u32(buffer[4:8])
	if WIN_CERT_ADDRESS != 0 && WIN_CERT_SIZE != 0 {

		buffer = make([]byte, 2)
		f.Seek(int64(WIN_CERT_ADDRESS)+6, 0)
		f.Read(buffer)
		wCertificateType := u16(buffer)

		switch wCertificateType {
		case WIN_CERT_TYPE_X509:
			info += pad("Authenticode", "Disabled (X.509 Certificate Not Supported)")
		case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
			info += pad("Authenticode", "Enabled")
		case WIN_CERT_TYPE_RESERVD_1:
			info += pad("Authenticode", "Disabled (Reserved)")
		case WIN_CERT_TYPE_TS_STACK_SIGNED:
			info += pad("Authenticode", "Disabled (Terminal Server Protocol Stack Certificate Not Supported)")
		default:
			info += pad("Authenticode", fmt.Sprintf("Disabled (type 0x%04X)", wCertificateType))
		}
	} else {
		info += pad("Authenticode", "Disabled")
	}
	return info
}

func findMachine(f *os.File, e_lfanew int64) {
	machine := make([]byte, 2)
	_, err := f.Seek(e_lfanew+4, 0)
	if err != nil {
		fmt.Println("Error setting offset to Machine: ", err)
	}
	_, err = f.Read(machine)
	if err != nil {
		fmt.Println("Error reading Machine: ", err)
	}
	machineValue := binary.LittleEndian.Uint16(machine)
	switch machineValue {
	case 0x0:
		fmt.Print(pad("Machine", "UNKNOWN"))
	case 0x184:
		fmt.Print(pad("Machine", "ALPHA"))
	case 0x284:
		fmt.Print(pad("Machine", "ALPHA64 / AXP64"))
	case 0x1d3:
		fmt.Print(pad("Machine", "AM33"))
	case 0x8664:
		fmt.Print(pad("Machine", "AMD64 (x64)"))
	case 0x1c0:
		fmt.Print(pad("Machine", "ARM"))
	case 0xaa64:
		fmt.Print(pad("Machine", "ARM64"))
	case 0xA641:
		fmt.Print(pad("Machine", "ARM64EC"))
	case 0xA64E:
		fmt.Print(pad("Machine", "ARM64X"))
	case 0x1c4:
		fmt.Print(pad("Machine", "ARMNT (Thumb-2)"))
	case 0xebc:
		fmt.Print(pad("Machine", "EBC (EFI Byte Code)"))
	case 0x14c:
		fmt.Print(pad("Machine", "I386 (Intel 386)"))
	case 0x200:
		fmt.Print(pad("Machine", "IA64 (Itanium)"))
	case 0x6232:
		fmt.Print(pad("Machine", "LoongArch32"))
	case 0x6264:
		fmt.Print(pad("Machine", "LoongArch64"))
	case 0x9041:
		fmt.Print(pad("Machine", "M32R"))
	case 0x266:
		fmt.Print(pad("Machine", "MIPS16"))
	case 0x366:
		fmt.Print(pad("Machine", "MIPSFPU"))
	case 0x466:
		fmt.Print(pad("Machine", "MIPSFPU16"))
	case 0x1f0:
		fmt.Print(pad("Machine", "PowerPC"))
	case 0x1f1:
		fmt.Print(pad("Machine", "PowerPCFP"))
	case 0x160:
		fmt.Print(pad("Machine", "R3000BE (MIPS Big Endian)"))
	case 0x162:
		fmt.Print(pad("Machine", "R3000 (MIPS Little Endian)"))
	case 0x166:
		fmt.Print(pad("Machine", "R4000 (MIPS III)"))
	case 0x168:
		fmt.Print(pad("Machine", "R10000 (MIPS IV)"))
	case 0x5032:
		fmt.Print(pad("Machine", "RISC-V 32"))
	case 0x5064:
		fmt.Print(pad("Machine", "RISC-V 64"))
	case 0x5128:
		fmt.Print(pad("Machine", "RISC-V 128"))
	case 0x1a2:
		fmt.Print(pad("Machine", "SH3"))
	case 0x1a3:
		fmt.Print(pad("Machine", "SH3DSP"))
	case 0x1a6:
		fmt.Print(pad("Machine", "SH4"))
	case 0x1a8:
		fmt.Print(pad("Machine", "SH5"))
	case 0x1c2:
		fmt.Print(pad("Machine", "THUMB"))
	case 0x169:
		fmt.Print(pad("Machine", "WCEMIPSV2"))
	default:
		fmt.Print(pad("Machine", "Unknown"))
	}
}

func isDotNETDirectory(f *os.File, e_lfanew int64) bool {
	buffer := make([]byte, 4)
	if pe == PE32 {
		f.Seek(int64(e_lfanew+0x18+0x60+0xe*8), 0)
	} else {
		f.Seek(int64(e_lfanew+0x18+0x70+0xe*8), 0)
	}
	f.Read(buffer)
	COM_DESCRIPTOR_RVA := u32(buffer)
	if COM_DESCRIPTOR_RVA != 0 {
		return true
	} else {
		return false
	}
}

func main() {
	// Usage
	if len(os.Args) < 2 || os.Args[1] == "-v" {
		fmt.Println("wchecksec 1.1.1")
		fmt.Printf("Usage: %s <file.exe>\n", os.Args[0])
		os.Exit(1)
	}

	for _, file := range os.Args[1:] {
		// open file
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %s\n", err)
			os.Exit(1)
		}
		defer f.Close()
		fmt.Printf("'%s'\n", file)

		// find PE signature address
		buffer := make([]byte, 4)
		_, err = f.Seek(0x3c, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting offset to PE_SIGNATURE: %s\n", err)
			os.Exit(1)
		}
		f.Read(buffer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading PE_SIGNATURE: %s\n", err)
			os.Exit(1)
		}
		e_lfanew = u32(buffer)

		// find Machine
		findMachine(f, int64(e_lfanew))

		// find IMAGE magic
		IMAGE_magic := make([]byte, 2)
		_, err = f.Seek(int64(e_lfanew+0x18), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting offset to IMAGE_MAGIC: %s\n", err)
		}
		_, err = f.Read(IMAGE_magic)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading IMAGE_MAGIC: %s\n", err)
		}
		if bytes.Equal(IMAGE_magic, PE32_IMAGE_MAGIC) {
			pe = PE32
			//fmt.Print(pad("Type", "PE32"))
		} else {
			pe = PE64
			//fmt.Print(pad("Type", "PE32+"))
		}

		// find IMAGE base
		if pe == PE32 {
			buffer = make([]byte, 4)
			f.Seek(int64(e_lfanew+0x18+0x1c), 0)
			f.Read(buffer)
			IMAGE_BASE = uint64(u32(buffer))
		} else {
			buffer = make([]byte, 8)
			f.Seek(int64(e_lfanew+0x18+0x18), 0)
			f.Read(buffer)
			IMAGE_BASE = u64(buffer)
		}

		// find NumberOfRvaAndSizes
		buffer = make([]byte, 4)
		if pe == PE32 {
			_, err = f.Seek(int64(e_lfanew+0x18+0x5c), 0)
		} else {
			_, err = f.Seek(int64(e_lfanew+0x18+0x6c), 0)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting offset to IMAGE_NUMBER_OF_RVA_AND_SIZES: %s\n", err)
		}
		_, err = f.Read(buffer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading IMAGE_NUMBER_OF_RVA_AND_SIZES: %s\n", err)
		}
		numberOfRvaAndSizes = u32(buffer)

		// find NumberOfSections
		buffer = make([]byte, 2)
		_, err = f.Seek(int64(e_lfanew+0x6), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting offset to FILE_NUMBER_OF_SECTIONS: %s\n", err)
		}
		_, err = f.Read(buffer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading FILE_NUMBER_OF_SECTIONS: %s\n", err)
		}
		numberOfSections = u16(buffer)

		// find DLLCharacteristics
		buffer = make([]byte, 2)
		_, err = f.Seek(int64(e_lfanew+0x18+0x46), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting offset to IMAGE_DLLCharacteristics: %s\n", err)
		}
		_, err = f.Read(buffer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading IMAGE_DLLCharacteristics: %s\n", err)
		}
		DLLCharacteristics := u16(buffer)

		// Parse protections
		fmt.Print(parseDLLCharacteristics(f, DLLCharacteristics))

		// Check .NET directory
		if isDotNETDirectory(f, int64(e_lfanew)) {
			fmt.Println(pad(".NET", "Yes"))
		} else {
			fmt.Println(pad(".NET", "No"))
		}
	}
}
