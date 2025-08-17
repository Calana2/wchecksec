# wchecksec
Check PE protections (ASLR, DEP, CFG, SafeSEH, GS)

Compile for Windows: `go build -o wchecksec wchecksec.go`

Compile for Windows in Linux Environment: `go GOOS="windows" GOARCH="amd64" build wchecksec.go`

