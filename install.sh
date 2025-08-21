#!/bin/bash

echo "Installing..."
go build -o ./bin/wchecksec wchecksec.go
cp -R ./bin/* /usr/local/bin
echo "Done."

