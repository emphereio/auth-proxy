DOCKER_REGISTRY=us-central1-docker.pkg.dev/eka-dev-418502/eka-test-helm-repo
IMAGE_NAME=auth-proxy
VERSION?=latest
DOCKER_IMAGE=$(DOCKER_REGISTRY)/$(IMAGE_NAME):$(VERSION)

# Docker commands
.PHONY: docker-build
docker-build:
	docker build --platform linux/amd64 \
		--no-cache \
		--compress \
		-t $(DOCKER_IMAGE) .

.PHONY: docker-push
docker-push:
	docker push $(DOCKER_IMAGE)

# Combined commands
.PHONY: deploy
deploy: docker-build docker-push