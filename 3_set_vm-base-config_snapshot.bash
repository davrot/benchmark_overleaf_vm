#!/usr/bin/env bash
# Wait until all the installation processes are done
virsh -c qemu:///session snapshot-create-as overleaf-base-config --name "Base" --description "Installation complete"
virsh -c qemu:///session snapshot-list overleaf-base-config

