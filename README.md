# Prepare the system

```
sudo chmod +x *.bash
```

## Install tools

The should install the qemu and co tools under Fedora or Ubuntu
```
sudo ./0_setup-kvm.bash
```
Now we will stay in userspace to keep every isolated. 

## Create the basis VM

The basis VM contains an Unntu 24LTS with node / npm / playwright, go, JAVA / maven tools. Furthermore, it contains the fresh overleaf code. 

```
./1_create-vm-base-config.bash
```

## Create a snapshot

We want a snapshot of the basis VM to which we can revert to. This gives us a clean and defined working space. 

First we wait until the basis VM is really done, then: 
```
./3_set_vm-base-config_snapshot.bash
```
# Dev container

## Create the dev compiled VM

For creating and testing e2e tests, we need a compiled set of dev containers. This takes some compile time, which we don't want to run if possible. 

Hence, we clone the basis VM (the basis VM needs to be shutdown for this operation)
```
./4_shutdown_vm.bash
./D1_clone.bash
```

Next we start the build process. Or in other words: We run this
```
cd /workspace/main/develop && ./bin/build
docker build texlive -t texlive-full
cd /workspace/main/services/git-bridge && docker build -t writelatex-git-bridge .
docker pull 8.4-alpine
docker pull mongo:8.0
```
inside the container via ssh. 

This script does this for you:
```
./D2_build.bash
```

Now we wait. A long time... until we see "✅ Build complete on overleaf-dev_build"

```
./D4_set_vm-dev_build_snapshot.bash
```

## Run the dev containers
We bring the container up with:
```
./D5_docker_container_up.bash
```
We automatically create the admin user
```
EMAIL="llm@lmm.lmm"
PASSWORD="LLM2LLM2LLM"
```
with
```
./D6_make_overleaf_admin_user.bash
```

## Connect to the overleaf session in the container

We use a ssh port forwarding to make the internal http server visable to our browser under 
http://127.0.0.1:8880
```
EMAIL="llm@lmm.lmm"
PASSWORD="LLM2LLM2LLM"
```

Use
```
./D7_open_ssh_tunnel.bash
```
or use
```
export SSH_PORT=2223
echo local http port: 8880
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no -L 8880:127.0.0.1:80 ubuntu@localhost
```
The ssh connection needs to be open otherwise the connection to the http server stops. 

If this ssh connection times out to often, we need to run this:
```
export SSH_PORT=2223
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  echo "ClientAliveInterval 60" > /etc/ssh/sshd_config.d/keepalive.conf
  echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config.d/keepalive.conf
  systemctl restart sshd
EOF
```

## TODO (dev containers)

* The LaTex compile does not work fully. SyncTex and compiling of images does not work correctly. 

# Production system 

## Create the production compiled VM

For creating and testing e2e tests, we may want to use the production docker containers. This takes some compile time, which we don't want to run if possible. 

Hence, we clone the basis VM (the basis VM needs to be shutdown for this operation)
```
./4_shutdown_vm.bash
./P1_clone.bash
```

Next we start the build process. This script does this for you:
```
./P2_build.bash
```

Now we wait. A long time... until we see "✅ Build complete on overleaf-production_build"

```
./P4_set_vm-production_build_snapshot.bash
```

## Run the dev containers
We bring the container up with:
```
./P5_docker_container_up.bash
```
We automatically create the admin user
```
EMAIL="llm@lmm.lmm"
PASSWORD="LLM2LLM2LLM"
```
with
```
./P6_make_overleaf_admin_user.bash
```

## Connect to the overleaf session in the container

We use a ssh port forwarding to make the internal http server visable to our browser under 
http://127.0.0.1:8880
```
EMAIL="llm@lmm.lmm"
PASSWORD="LLM2LLM2LLM"
```

Use
```
./P7_open_ssh_tunnel.bash
```
or use
```
export SSH_PORT=2226
echo local https port: 8881
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no -L 8881:overleaf.local:443 ubuntu@localhost
```
The ssh connection needs to be open otherwise the connection to the https server stops. 

If this ssh connection times out to often, we need to run this:
```
export SSH_PORT=2226
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  echo "ClientAliveInterval 60" > /etc/ssh/sshd_config.d/keepalive.conf
  echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config.d/keepalive.conf
  systemctl restart sshd
EOF
```

