default: ## Debug build
	cargo build

clean: ## Clean all build artifacts and dependencies
	@cargo clean

coverage: ## Generate HTML code coverage
	cargo tarpaulin -t 1200 --out Html

dev-env: ## Download development dependencies
	cargo fetch

doc: ## Prepare documentation
	cargo doc --no-deps --workspace --all-features

lint: ## Lint codebase
	cargo fmt -v --all -- --emit files
	cargo clippy --workspace --tests --all-features

test: ## Run tests
	cargo test --all-features --no-fail-fast

xml-test-coverage: migrate  ## Generate cobertura.xml test coverage
	cargo tarpaulin -t 1200 --out Xml

help: ## Prints help for targets with comments
	@cat $(MAKEFILE_LIST) | grep -E '^[a-zA-Z_-]+:.*?## .*$$' | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
