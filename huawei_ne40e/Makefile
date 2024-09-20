VENDOR=Huawei
NAME=NE40E
IMAGE_FORMAT=qcow2
IMAGE_GLOB=*.qcow2

# match versions like:
# huawei_ne40e-<any version string>.qcow2
VERSION=$(shell echo $(IMAGE) | sed -e 's/huawei_ne40e-\(.*\)\.qcow2/\1/')

-include ../makefile-sanity.include
-include ../makefile.include
