.PHONY: all build image push imageonly vpp vpp-build-env

VPPLINK_DIR=../vpplink
INIT_EKS_IMAGE_DIR=images/init-eks/
DEV_IMAGE_DIR=images/dev/
TAG ?= latest

all: image

build:
	GOOS=linux go build -o $(IMAGE_DIR)/vpp-manager

eksimage:
	docker build --pull \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/init-eks:$(TAG) $(INIT_EKS_IMAGE_DIR)

image: build vpp
	docker build --pull \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)

push: image
	docker push calicovpp/vpp:$(TAG)

imageonly: build
	docker build --pull \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)

vpp: vpp-build-env
	bash $(VPPLINK_DIR)/binapi/vpp_clone_current.sh ./vpp_build
	docker run --rm \
		-v $(CURDIR):/root/vpp-manager:delegated \
		calicovpp/vpp-build:latest
	rm -f $(IMAGE_DIR)*.deb
	for pkg in vpp vpp-plugin-core vpp-plugin-dpdk libvppinfra ; do \
		cp vpp_build/build-root/$$pkg_*.deb $(IMAGE_DIR) ; \
	done

vpp-build-env:
	docker build \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp-build:latest images/ubuntu-build

dev: build
	docker build --pull \
	  --build-arg http_proxy=${DOCKER_BUILD_PROXY} \
	  -t calicovpp/vpp:$(TAG) $(DEV_IMAGE_DIR)
