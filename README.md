# wchecksec
#### Check PE protections: ASLR, DEP, CFG, SafeSEH, GS, Isolation, Force Integrity, Authenticode
**Built from scratch in Go.**

## PE Protections Checked
- [x] **ASLR**                
  - Base
  - High Entropy
  - Stripped relocations
- [x] **GS**               
  - Entry Load Config Directory assertion
  - Heuristic pattern search
- [x] **DEP**                   
- [x] **CFG**                       
- [x] **SafeSEH**               
- [x] **Isolation**             
- [x] **Force Integrity**
- [x] **Authenticode**     

## Miscellaneous Information
- Machine               (Architecture)
- .NET verification

## Build & Install
```
git clone https://github.com/Calana2/wchecksec.git
cd wchecksec
chmod u+x install.sh
sudo ./install.sh
```

