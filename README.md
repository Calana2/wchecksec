# wchecksec
#### Check PE protections: ASLR, DEP, CFG, SafeSEH, GS, Isolation, Force Integrity, Authenticode

**A go script and a python script for Ghidra.**

## PE Protections Checked
- [x] **ASLR**                
  - Base
  - High Entropy
  - Stripped relocations
- [x] **GS**               
  - Entry Load Config Directory assertion
  - Heuristic pattern search (TODO in the ghidra script)
- [x] **DEP**                   
- [x] **CFG**                       
- [x] **SafeSEH**               
- [x] **Isolation**             
- [x] **Force Integrity**
- [x] **Authenticode**     

## Miscellaneous Information 
- Machine               (Architecture)
- .NET verification

## Build & Install (standalone go binary - Linux)
```
git clone https://github.com/Calana2/wchecksec.git
cd wchecksec
chmod u+x install.sh
sudo ./install.sh
```

## Ghidra Script - Installation
1. Open any file in Ghidra for analysis
2. Select the Window / Script Manager menu
3. Click the "Script Directories" icon in the upper right toolbar
4. Add this directory script via the green plus sign

Or just add the script to an existing valid directory.



