VENDOR=Huawei
NAME=VRP
IMAGE_FORMAT=qcow2
IMAGE_GLOB=*.qcow2

# match versions like:
# NE40E_V800R011C00SPC607B607.qcow2
VERSION=$(shell echo $(IMAGE) | sed -e 's/.*\(V[0-9][0-9][0-9]R[0-9][0-9][0-9]C[0-9][0-9]SPC[0-9][0-9][0-9]\)T\?\(.*\|$$\)/\1/')

-include ../makefile-sanity.include
-include ../makefile.include
