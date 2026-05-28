.PHONY: all build clean run test fmt setup loadtest lint build-docker systest systest-ggsh systest-linux

all: setup
	cargo build --release

setup:
	./script/setup-protoc.sh

build:
ifndef version
	$(error version is required. Usage: make build version=v0.1.0 [platform=linux/amd64])
endif
	./script/build.sh $(version) $(platform)

build-docker: build
ifndef version
	$(error version is required. Usage: make build-docker version=v0.1.0 [platform=linux/amd64])
endif
	./bgpgg/docker/build.sh $(version) $(platform)

clean:
	cargo clean

run: setup
	cargo run

lint: setup
	cargo clippy --all-targets --all-features -- -D warnings

test: lint
	cargo build --bin bgpggd --bin ggsh
	cargo test --workspace --exclude loadtests --no-fail-fast -- --nocapture

fmt:
	cargo fmt

loadtest: setup
	@echo "Building bgpggd and running load tests..."
	cargo build --bin bgpggd --release
	cargo test -p loadtests --release -- --nocapture --test-threads=1

systest: setup
	cargo build --release --bin bgpggd --bin ggsh
	./systests/basic.sh

systest-ggsh: setup
	cargo build --release --bin bgpggd --bin ggsh
	./systests/ggsh.sh

systest-linux: setup
	cargo build --release --bin bgpggd --bin ggsh
	sudo ./systests/linux.sh
