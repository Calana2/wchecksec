#!/bin/bash

echo "Installing..."
if [ ! -d "./bin" ]; then
  mkdir ./bin
fi
go build -o ./bin/wchecksec wchecksec.go
cp -R ./bin/* /usr/local/bin
rm ./bin/wchecksec
echo "Done."

