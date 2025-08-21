package main

/* Spaguetti code go!
 */

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
	DLLC_NXCompatible                   = 0x100
	DLLC_NoSeh                          = 0x400
	DLLC_ControlFlowGuard               = 0x4000
)

const (
	PE32 = iota
	PE64
)

var f *os.File
var pe int8
var e_lfanew uint32
var IMAGE_BASE uint64
var numberOfRvaAndSizes uint32
var numberOfSections uint16

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

func u64(b []byte) uint64 { return  binary.LittleEndian.Uint64(b) }
func u32(b []byte) uint32 { return  binary.LittleEndian.Uint32(b) }
func u16(b []byte) uint16 { return  binary.LittleEndian.Uint16(b) }

func parseSectionHeaders(f *os.File, IMAGE_SECTION_BASE uint32) []*IMAGE_SECTION_HEADER {
	var headers []*IMAGE_SECTION_HEADER
	f.Seek(int64(IMAGE_SECTION_BASE), 0)
	buffer := make([]byte, numberOfSections*0x28)
	f.Read(buffer)
	for i := 0; i < int(numberOfSections); i++ {
		base := 0x28 * i
		sh := &IMAGE_SECTION_HEADER{}
		sh.Name = string(buffer[base:base+8])
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
	return fmt.Sprintf("%-15s%s\n", def+":", msg)
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
	var sectionHeaders []*IMAGE_SECTION_HEADER = parseSectionHeaders(f, uint32(IMAGE_SECTION_HEADER_BASE))

	// ** ASLR (Address Space Layout Randomization)**
	if v&DLLC_DynamicBase != 0 {
		hasReloc := false
		for _, section := range sectionHeaders {
			if strings.Contains(section.Name,".reloc") {
				hasReloc = true
				break
			}
		}
		// no relocs!
		if !hasReloc {
			hasASLR = false
			info += pad("ASLR", "disabled (no relocations)")
		} else {
			// high entropy
			if v&DLLC_HighEntropyVirtualAddressSpace != 0 {
				info += pad("ASLR", "enabled (high entropy)")
			} else {
				// base
				info += pad("ASLR", "enabled (base)")
			}
		}
	} else {
		hasASLR = false
		info += pad("ASLR", "disabled")
	}

	// Print OPTIONAL_HEADER.IMAGE_BASE
	if !hasASLR {
		info += fmt.Sprintf("%-15s0x%x\n", "Image Base:", IMAGE_BASE)
	}

	// ** DEP (Data Execution Prevention) **
	if v&DLLC_NXCompatible != 0 {
		info += pad("DEP", "enabled")
	} else {
		info += pad("DEP", "disabled")
	}

	// ** CFG (Control Flow Guard) **
	if v&DLLC_ControlFlowGuard != 0 {
		info += pad("CFG", "enabled")
	} else {
		info += pad("CFG", "disabled")
	}
	// find IMAGE_DATA_DIRECTORY[] LOAD_CONFIG
	buffer = make([]byte, 4)
	if pe == PE32 {
		f.Seek(int64(e_lfanew+0x18+0x60+10*8), 0)
	} else {
		f.Seek(int64(e_lfanew+0x18+0x70+10*8), 0)
	}
	f.Read(buffer)
	ENTRY_LOAD_CONFIG_RVA := u32(buffer)
	ENTRY_LOAD_CONFIG_ADDRESS := rvaToOffset(ENTRY_LOAD_CONFIG_RVA, sectionHeaders)
	ConfigDirectory := parseLoadConfigDirectory(f, ENTRY_LOAD_CONFIG_ADDRESS, pe == PE64)

	// ** SafeSEH (Safe Structured Exception Handler) **
	if pe == PE64 {
		info += pad("SafeSEH", "disabled (not available for 64-bit binaries)")
	} else if v&DLLC_NoSeh != 0 {
		info += pad("SafeSEH", "disabled")
	} else {
		if ENTRY_LOAD_CONFIG_ADDRESS == 0 {
			info += pad("SafeSEH", "disabled")
		} else {
			if ConfigDirectory.SEHandlerTable == 0 {
				info += pad("SafeSEH", "disabled")
			} else {
				info += pad("SafeSEH", "enabled")
			}
		}
	}
	// ** GS (Buffer security check) **
	if ENTRY_LOAD_CONFIG_ADDRESS == 0 || ConfigDirectory.SecurityCookie == 0 {
		info += pad("GS", "disabled")
	} else {
    // ConfigDirectory.SecurityCookie is a VA
    SecurityCookieRVA := uint32(ConfigDirectory.SecurityCookie - IMAGE_BASE)
		f.Seek(int64(rvaToOffset(SecurityCookieRVA,sectionHeaders)), 0)
		buffer := make([]byte, 8)
    f.Read(buffer)
		if pe == PE64 {
			info += pad("GS", fmt.Sprintf("enabled  (stack_cookie=0x%x)\n", u64(buffer)))
		} else {
			info += pad("GS", fmt.Sprintf("enabled  (stack_cookie=0x%x)\n", u32(buffer[:4])))
		}
	}
	return info
}

func main() {
	// Usage
	if (len(os.Args)) < 2 {
		fmt.Printf("Usage: %s <file.exe>\n", os.Args[0])
		os.Exit(1)
	} else if os.Args[1] == "-v" {
		fmt.Println("wchecksec 1.0.1")
		os.Exit(1)
	}

	for _, file := range os.Args[1:] {
		// open file
		f, err := os.Open(file)
		if err != nil {
			fmt.Println("Error opening file: ", err)
			os.Exit(1)
		}
    defer f.Close()
		fmt.Printf("'%s'\n", file)

		// find PE signature address
		buffer := make([]byte, 4)
		_, err = f.Seek(0x3c, 0)
		if err != nil {
			fmt.Println("Error setting offset to PE_SIGNATURE: ", err)
		}
		f.Read(buffer)
		if err != nil {
			fmt.Println("Error reading PE_SIGNATURE: ", err)
		}
		e_lfanew = u32(buffer)

		// find IMAGE magic
		IMAGE_magic := make([]byte, 2)
		_, err = f.Seek(int64(e_lfanew+0x18), 0)
		if err != nil {
			fmt.Println("Error setting offset to IMAGE_MAGIC: ", err)
		}
		_, err = f.Read(IMAGE_magic)
		if err != nil {
			fmt.Println("Error reading IMAGE_MAGIC: ", err)
		}
		if bytes.Equal(IMAGE_magic, PE32_IMAGE_MAGIC) {
			pe = PE32
			fmt.Print(pad("Type", "PE32"))
		} else {
			pe = PE64
			fmt.Print(pad("Type", "PE32+"))
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
			fmt.Println("Error setting offset to IMAGE_NUMBER_OF_RVA_AND_SIZES: ", err)
		}
		_, err = f.Read(buffer)
		if err != nil {
			fmt.Println("Error reading IMAGE_NUMBER_OF_RVA_AND_SIZES: ", err)
		}
		numberOfRvaAndSizes = u32(buffer)

		// find NumberOfSections
		buffer = make([]byte, 2)
		_, err = f.Seek(int64(e_lfanew+0x6), 0)
		if err != nil {
			fmt.Println("Error setting offset to FILE_NUMBER_OF_SECTIONS: ", err)
		}
		_, err = f.Read(buffer)
		if err != nil {
			fmt.Println("Error reading FILE_NUMBER_OF_SECTIONS: ", err)
		}
		numberOfSections = u16(buffer)

		// find DLLCharacteristics
		buffer = make([]byte, 2)
		_, err = f.Seek(int64(e_lfanew+0x18+0x46), 0)
		if err != nil {
			fmt.Println("Error setting offset to IMAGE_DLLCharacteristics: ", err)
		}
		_, err = f.Read(buffer)
		if err != nil {
			fmt.Println("Error reading IMAGE_DLLCharacteristics: ", err)
		}
		DLLCharacteristics := u16(buffer)

		// Parse protections
		fmt.Println(parseDLLCharacteristics(f, DLLCharacteristics))
	}
}
