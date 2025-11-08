# checksec_calana_pe.py
# -*- coding: UTF-8 -*-
# @author Calana2
# @category PE Tools
# @runtime Jython

# There should be a faster and simpler way using the API but I dont know too much about it, Im just learning

from ghidra.program.model.address import Address
from ghidra.util import Msg

mem = currentProgram.getMemory()
imageBase = currentProgram.getImageBase()
base_off = imageBase.getOffset()

from java.io import RandomAccessFile
import jarray

def read_file_bytes(f, offset, size):
    buf = jarray.zeros(size, 'b')  # bytearray
    f.seek(offset)
    f.read(buf)
    return [b & 0xFF for b in buf]

def read_file_uint16(f, offset):
    b = read_file_bytes(f, offset, 2)
    return b[0] | (b[1] << 8)

def read_file_uint32(f, offset):
    b = read_file_bytes(f, offset, 4)
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)

def read_uint32(offset):
    return mem.getInt(toAddr(offset)) & 0xFFFFFFFF

def read_uint16(offset):
    return mem.getShort(toAddr(offset)) & 0xFFFF

def detect_machine(machineValue):
    if machineValue == 0x0:
        return "UNKNOWN"
    elif machineValue == 0x184:
        return "ALPHA"
    elif machineValue == 0x284:
        return "ALPHA64 / AXP64"
    elif machineValue == 0x1d3:
        return "AM33"
    elif machineValue == 0x8664:
        return "AMD64 (x64)"
    elif machineValue == 0x1c0:
        return "ARM"
    elif machineValue == 0xaa64:
        return "ARM64"
    elif machineValue == 0xA641:
        return "ARM64EC"
    elif machineValue == 0xA64E:
        return "ARM64X"
    elif machineValue == 0x1c4:
        return "ARMNT (Thumb-2)"
    elif machineValue == 0xebc:
        return "EBC (EFI Byte Code)"
    elif machineValue == 0x14c:
        return "I386 (Intel 386)"
    elif machineValue == 0x200:
        return "IA64 (Itanium)"
    elif machineValue == 0x6232:
        return "LoongArch32"
    elif machineValue == 0x6264:
        return "LoongArch64"
    elif machineValue == 0x9041:
        return "M32R"
    elif machineValue == 0x266:
        return "MIPS16"
    elif machineValue == 0x366:
        return "MIPSFPU"
    elif machineValue == 0x466:
        return "MIPSFPU16"
    elif machineValue == 0x1f0:
        return "PowerPC"
    elif machineValue == 0x1f1:
        return "PowerPCFP"
    elif machineValue == 0x160:
        return "R3000BE (MIPS Big Endian)"
    elif machineValue == 0x162:
        return "R3000 (MIPS Little Endian)"
    elif machineValue == 0x166:
        return "R4000 (MIPS III)"
    elif machineValue == 0x168:
        return "R10000 (MIPS IV)"
    elif machineValue == 0x5032:
        return "RISC-V 32"
    elif machineValue == 0x5064:
        return "RISC-V 64"
    elif machineValue == 0x5128:
        return "RISC-V 128"
    elif machineValue == 0x1a2:
        return "SH3"
    elif machineValue == 0x1a3:
        return "SH3DSP"
    elif machineValue == 0x1a6:
        return "SH4"
    elif machineValue == 0x1a8:
        return "SH5"
    elif machineValue == 0x1c2:
        return "THUMB"
    elif machineValue == 0x169:
        return "Unknown or missing entry"
    else:
        return "UNRECOGNIZED"

def has_dotNET_directory(image_data_directory_off):
    com_descriptor_rva = read_uint32(image_data_directory_off + 8 * 0xe)
    if com_descriptor_rva != 0:
        return "Yes"
    return "No"

DLLC_HighEntropyVirtualAddressSpace = 0x32
DLLC_DynamicBase = 0x40
DLLC_ForceIntegrity = 0x80
DLLC_NXCompatible = 0x100
DLLC_NoIsolation = 0x200
DLLC_NoSeh = 0x400
DLLC_ControlFlowGuard = 0x4000

WIN_CERT_TYPE_X509 = 0x0001
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
WIN_CERT_TYPE_RESERVD_1 = 0x0003
WIN_CERT_TYPE_TS_STACK_SIGNED = 0x0004

# relevant data
cfg = ""
dep = ""
aslr = ""
safe_seh = ""
gs = ""
isolation = ""
force_integrity = ""
authenticode = ""
dot_net = ""

def parse_cert_type(wCertificateType):
    if wCertificateType == WIN_CERT_TYPE_X509:
        return "Disabled (X.509 Certificate Not Supported)"
    elif wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA:
        return "Enabled"
    elif wCertificateType == WIN_CERT_TYPE_RESERVD_1:
        return "Disabled (Reserved)"
    elif wCertificateType == WIN_CERT_TYPE_TS_STACK_SIGNED:
        return "Disabled (Terminal Server Protocol Stack Certificate Not Supported)"
    else:
        return "Disabled (type 0x%04X)" % wCertificateType

def parse_DllCharacteristics(dllc, magic):
    global aslr, dep, cfg, safe_seh, gs, isolation, force_integrity, authenticode

    # [+] IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> IMAGE_DATA_DIRECTORY -> LOAD_CONFIG
    load_config_address = 0
    load_config_rva = read_uint32(image_data_directory_off + 8 * 0xA)
    if load_config_rva != 0:
        load_config_address = base_off + load_config_rva

    # ASLR
    if dllc & DLLC_DynamicBase:
        has_reloc = False
        for section in mem.getBlocks():
            if ".reloc" in section.name:
                has_reloc = True
                break
        if not has_reloc:
            aslr = "Disabled (No Relocations)"
        elif dllc & DLLC_HighEntropyVirtualAddressSpace:
            aslr = "Enabled (High Entropy)"
        else:
            aslr = "Enabled"
    else:
        aslr = "Disabled"

    # DEP
    if dllc & DLLC_NXCompatible:
        dep = "Enabled"
    else:
        dep = "Disabled"

    # CFG
    if dllc & DLLC_ControlFlowGuard:
        cfg = "Enabled"
    else:
        cfg = "Disabled"

    # SafeSEH
    if magic == 0x20b:
        safe_seh = "Disabled (not available for 64-bit binaries)"
    elif dllc & DLLC_NoSeh:
        safe_seh = "Disabled"
    else:
        if load_config_address == 0:
            safe_seh = "Disabled"
        else:
            if magic == 0x10b:   # PE32
                se_offset = 0x40
                try:
                    sehandler_table = read_uint32(load_config_address + se_offset)
                except:
                    sehandler_table = 0
            else:                # PE32+ (64-bit)
                se_offset = 0x60
                try:
                    sehandler_table = mem.getLong(toAddr(load_config_address + se_offset)) & 0xFFFFFFFFFFFFFFFF
                except:
                    sehandler_table = 0

            if sehandler_table == 0:
                safe_seh = "Disabled"
            else:
                safe_seh = "Enabled"

    # GS
    if load_config_address == 0:
        if dot_net == "Yes":
            gs = "Disabled"
        else:
            gs = "Disabled"
            # TODO: Heuristic search
    else:
        try:
            if magic == 0x10b:   # PE32
                security_cookie_va = read_uint32(load_config_address + 0x3c)
            else:                # PE32+ (64-bit)
                security_cookie_va = mem.getLong(toAddr(load_config_address + 0x58)) & 0xFFFFFFFFFFFFFFFF
        except:
            security_cookie_va = 0

        if security_cookie_va == 0:
            gs = "Disabled"
        else:
            # security_cookie_va is a VA. Read cookie from memory using VA.
            try:
                if magic == 0x10b:
                    cookie_value = mem.getInt(toAddr(security_cookie_va)) & 0xFFFFFFFF
                    gs = "Enabled (stack_cookie=0x%x)" % cookie_value
                else:
                    cookie_value = mem.getLong(toAddr(security_cookie_va)) & 0xFFFFFFFFFFFFFFFF
                    gs = "Enabled (stack_cookie=0x%x)" % cookie_value
            except:
                gs = "Enabled (stack_cookie=unreadable)"

    # Isolation
    if dllc & DLLC_NoIsolation:
        isolation = "Disabled"
    else:
        isolation = "Enabled"

    # Force Integrity
    if dllc & DLLC_ForceIntegrity:
        force_integrity = "Enabled"
    else:
        force_integrity = "Disabled"

    # Authenticode
    security_off = read_uint32(image_data_directory_off + 8 * 0x4)
    security_size = read_uint32(image_data_directory_off + 8 * 0x4 + 4)
    if security_off != 0 and security_size != 0:
        try:
            exe_path = currentProgram.getExecutablePath()
            f = RandomAccessFile(exe_path, "r")
            win_cert_type = read_file_uint16(f, security_off + 6)
            authenticode = parse_cert_type(win_cert_type)
            f.close()
        except Exception as e:
            authenticode = "Error reading cert (%s)" % str(e)
    else:
        authenticode = "Disabled"

try:
    # ----------------------------------------------------
    # [+] IMAGE_DOS_HEADER -> e_lfanew
    # ----------------------------------------------------
    e_lfanew = read_uint32(base_off + 0x3C)

    # ----------------------------------------------------
    # [+] IMAGE_NT_HEADERS -> Signature
    # ----------------------------------------------------
    nt_header = base_off + e_lfanew
    sig = read_uint32(nt_header)
    if sig != 0x00004550:  # PE\0\0
        raise Exception("[ERROR] Missing IMAGE_NT_HEADERS -> Signature")

    # ------------------------------------------------------------------------------------
    # [+] IMAGE_NT_HEADERS -> IMAGE_FILE_HEADER -> Machine
    # ------------------------------------------------------------------------------------
    file_header_off = nt_header + 4
    machine = detect_machine(read_uint16(file_header_off))

    # -----------------------------------------------------------------------------
    # [+] IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER
    # -----------------------------------------------------------------------------
    optional_header_off = file_header_off + 20

    # ------------------------------------------------------------------------------------------
    # [+] IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> Magic
    # ------------------------------------------------------------------------------------------
    magic = read_uint16(optional_header_off)
    if magic != 0x10b and magic != 0x20b:  # PE32 and PE32+
        raise Exception("[ERROR] Unknown IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> Magic")

    # ----------------------------------------------------------------------------------------------------------------------
    # [+] IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> IMAGE_DATA_DIRECTORY
    # ----------------------------------------------------------------------------------------------------------------------
    if magic == 0x10b:
        image_data_directory_off = optional_header_off + 0x60
    else:
        image_data_directory_off = optional_header_off + 0x70

    # ----------------------------------------------------------------------------------------------------------------------------------------------------
    # [+] IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> IMAGE_DATA_DIRECTORY -> COM_DESCRIPTOR
    # ----------------------------------------------------------------------------------------------------------------------------------------------------
    dot_net = has_dotNET_directory(image_data_directory_off)

    # -----------------------------------------------------------------------------------------------------------
    # [+] IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> DllCharacteristics
    # ----------------------------------------------------------------------------------------------------------
    dllchar_off = optional_header_off + 0x46
    dllchars = read_uint16(dllchar_off)
    parse_DllCharacteristics(dllchars, magic)

    # # ------------------------------------------------------------------------------------------
    # #                       OUTPUT
    # # ------------------------------------------------------------------------------------------
    print("=================================================================")
    print("Machine:".ljust(20) + machine)
    print("ASLR:".ljust(20) + aslr)
    print("DEP:".ljust(20) + dep)
    print("CFG:".ljust(20) + cfg)
    print("SafeSEH:".ljust(20) + safe_seh)
    print("GS:".ljust(20) + gs)
    print("Isolation:".ljust(20) + isolation)
    print("Force Integrity:".ljust(20) + force_integrity)
    print("Authenticode:".ljust(20) + authenticode)
    print(".NET:".ljust(20) + dot_net)
    print("=================================================================")

except Exception as e:
    println("Exception: %s" % e)
    Msg.showError(None, None, "PE parse error", str(e))
