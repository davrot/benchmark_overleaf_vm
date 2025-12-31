#!/usr/bin/env bash
# Wait until all the installation processes are done
virsh -c qemu:///session snapshot-create-as overleaf-dev_build --name "Compiled" --description "Compilation complete"
virsh -c qemu:///session snapshot-list overleaf-dev_build

