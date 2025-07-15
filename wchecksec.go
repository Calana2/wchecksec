package main

/* This program is highly unreadable, I'm sorry for that
 * After all, it is just an implementation for learning purposes.
*/
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"

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
var numberOfRvaAndSizes uint32
var numberOfSections uint16

var PE32_IMAGE_MAGIC = []byte{0x0b, 0x01}
var PE64_IMAGE_MAGIC = []byte{0x0b, 0x02}

func pad(def string, msg string, msgColor string) string {
	return fmt.Sprintf("%-15s%s\n", def+":", msgColor+msg+Reset)
}

func parseDLLCharacteristics(v uint16) string {
	var buffer []byte
	var info string
	var hasASLR bool = true
	var IMAGE_BASE uint64
	f, _ = os.Open(os.Args[1])

	// ASLR
	if v&DLLC_DynamicBase != 0 {
		hasReloc := false
		// iterate over section names
		var IMAGE_SECTION_HEADER_BASE int
		if pe == PE32 {
			IMAGE_SECTION_HEADER_BASE = int(e_lfanew + 0x18 + numberOfRvaAndSizes*8 + 0x60)
		} else {
			IMAGE_SECTION_HEADER_BASE = int(e_lfanew + 0x18 + numberOfRvaAndSizes*8 + 0x70)
		}
		for i := 0; i < int(numberOfSections); i++ {
			f.Seek(int64(IMAGE_SECTION_HEADER_BASE+0x28*i), 0)
			buffer = make([]byte, 8)
			f.Read(buffer)
			sectionName := string(bytes.TrimRight(buffer, "\x00"))
			if sectionName == ".reloc" {
				hasReloc = true
				break
			}
		}
		// no relocs!
		if !hasReloc {
			hasASLR = false
			info += pad("ASLR", "disabled (no relocations)", Yellow)
		} else {
			// high entropy
			if v&DLLC_HighEntropyVirtualAddressSpace != 0 {
				info += pad("ASLR", "enabled (high entropy)", Green)
			} else {
				// base
				info += pad("ASLR", "enabled (base)", Yellow)
			}
		}
	} else {
		hasASLR = false
		info += pad("ASLR", "disabled", Red)
	}

	// Get IMAGE_BASE
	if !hasASLR {
		if pe == PE32 {
			buffer = make([]byte, 4)
			f.Seek(int64(e_lfanew+0x18+0x1c), 0)
			f.Read(buffer)
			IMAGE_BASE = uint64(binary.LittleEndian.Uint32(buffer))
		} else {
			buffer = make([]byte, 8)
			f.Seek(int64(e_lfanew+0x18+0x18), 0)
			f.Read(buffer)
			IMAGE_BASE = binary.LittleEndian.Uint64(buffer)
		}
		info += fmt.Sprintf("%-15s" + Red + "0x%x\n" + Reset, "Image Base:",IMAGE_BASE)
	}

	// DEP
	if v&DLLC_NXCompatible != 0 {
		info += pad("DEP", "enabled", Green)
	} else {
		info += pad("DEP", "disabled", Red)
	}

	// CFG
	if v&DLLC_ControlFlowGuard != 0 {
		info += pad("CFG", "enabled", Green)
	} else {
		info += pad("CFG", "disabled", Red)
	}

	// SEH
	if pe == PE64 {
		info += pad("SafeSEH", "disabled (not available for 64-bit binaries)", Green)
	} else if v&DLLC_NoSeh != 0 {
		info += pad("SafeSEH", "disabled", Red)
	} else {
		// find IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
		buffer := make([]byte, 4)
		_, err := f.Seek(int64(e_lfanew+0x18+0xb0), 0)
		if err != nil {
			fmt.Println("Error setting offset to IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_RVA: ", err)
		}
		_, err = f.Read(buffer)
		if err != nil {
			fmt.Println("Error reading IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_RVA: ", err)
		}
		ENTRY_LOAD_CONFIG_RVA := binary.LittleEndian.Uint32(buffer)
		if ENTRY_LOAD_CONFIG_RVA == 0 {
			info += pad("SafeSEH", "disabled", Red)
		} else {
			info += pad("SafeSEH", "enabled", Green)
		}
	}
	return info
}

func main() {
  // Usage
  if(len(os.Args)) != 2 {
    fmt.Printf("Usage: %s <file.exe>\n",os.Args[0])
    os.Exit(1)
  }
   
	// open file
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error opening file: ", err)
		os.Exit(1)
	}
	fmt.Printf("'%s'\n", os.Args[1])

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
	e_lfanew = binary.LittleEndian.Uint32(buffer)

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
		fmt.Print(pad("Type", "PE32", ""))
	} else {
		pe = PE64
		fmt.Print(pad("Type", "PE32+", ""))
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
	numberOfRvaAndSizes = binary.LittleEndian.Uint32(buffer)

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
	numberOfSections = binary.LittleEndian.Uint16(buffer)

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
	DLLCharacteristics := binary.LittleEndian.Uint16(buffer)

	// Parse protections
	fmt.Println(parseDLLCharacteristics(DLLCharacteristics))
}
