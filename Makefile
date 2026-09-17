# Macky Merch API - entry points.
#
# Deliberately thin. Every target is a one-line wrapper around a command that
# already appears in the README, and none of them contain logic of their own.
#
# That is the whole design constraint: a Makefile that reimplements what CI does
# becomes a second source of truth, and the two drift. Then `make test` passes
# while the pipeline fails and nobody trusts either. These delegate - to npm, to
# docker, and to scripts/verify.sh, which is the same set of gates ci.yml runs.

IMAGE ?= macky-merch-api:local
PORT  ?= 3000

.DEFAULT_GOAL := help
.PHONY: help up down logs test build run verify scan clean

help: ## Show this help
	@echo "Macky Merch API - available targets:"
	@echo
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Start here:  make up     then  curl http://127.0.0.1:$(PORT)/health"

up: ## Start the app + Redis via Docker Compose
	docker compose up -d --build
	@echo "  -> http://127.0.0.1:$(PORT)/health"

down: ## Stop the Compose stack and remove its volumes
	docker compose down -v

logs: ## Tail logs from the Compose stack
	docker compose logs -f

build: ## Build the runtime image only
	docker build --target runtime -t $(IMAGE) .

run: build ## Build, then run the container on 127.0.0.1 only
	docker run --rm -p 127.0.0.1:$(PORT):3000 $(IMAGE)

test: ## Install dependencies and run the Jest suite on the host
	npm ci
	npm test

verify: ## Run all 12 gates locally - the same set ci.yml runs
	bash scripts/verify.sh

scan: build ## Scan the shipped image for fixable HIGH/CRITICAL CVEs
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
	  image $(IMAGE) --no-progress --scanners vuln \
	  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1

clean: ## Remove built images and the Compose stack
	-docker compose down -v
	-docker rmi $(IMAGE) macky-merch-api:test
