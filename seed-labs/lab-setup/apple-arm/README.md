# Building SEED VM for Apple Silicon Machines

As more and more people are using Apple machines with M1/M2
chips (Apple Silicon), it becomes important to provide 
a virtual machine for students to conduct the SEED labs 
on their person computer (we used to ask them to
do the labs the cloud). In this project, we are building 
a virtual machine for the Apple Silicon machine. 
We document the design choices, progress and the encountered 
issues in this project. 


## Choosing the Virtual Machine Software 

It does not seem that VirtualBox will allow us to run
Linux on top of Apple Silicon machines any time soon.
Other than the cloud approach, we should start looking at
other approaches. There are two possible virtualization
products:

- VMWare Fusion Player: this one is free. We choose to use this software.
  Here is the [instructions](./seedvm-fusion.md).

- Parallels: this one is not free.
  - If you have a Parallels subscription, you may follow the instructions provided in [src-vm](../ubuntu20.04-vm/src-vm/README.md)
  - Comment out the virtualbox specific scripts from [`main.sh`](../ubuntu20.04-vm/src-vm/main.sh)(`# Add guest addition`)before use.





## Building Docker Images for ARM64 

All our docker images were built for AMD64, so for each image, we need to build 
one for ARM. To use the same tag for both AMD64 and ARM64, 
we can use the multi-arch build approach.
The following command actually builds three images, one for each platform.
These images share the same tag. When users pull the image from the DockerHub, 
they can pull one specific to their platform. See our script `build.sh`. 

```
docker buildx build --push \
       --platform linux/arm64/v8,linux/amd64 \ 
       --tag handsonsecurity/seed-ubuntu:large-multi  .
```


Note: for now, let's separate the `amd64` and `arm64` images;
otherwise, we will have to rebuild all the images. 
There is a concern that some of the software may end up using a 
newer version, and might break some labs. Since most 
users use the `amd64` images, to avoid any risk, we will 
build separate images for `arm64` (appending `-arm` to 
the image tag). When we upgrade the SEED VM to the next version, we 
will switch to the multi-arch image, so the same image 
names are used for both platforms. 



## Lab Testing 

We will conduct testing for each SEED lab. 
The testing progress and results are described in 
[Lab_Testing.md](./Lab_Testing.md).

