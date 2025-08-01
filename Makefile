# Starkli config.
config := --account katana-0 \
	--rpc http://0.0.0.0:5050

# Build files helpers.
build := ./target/dev/controller_
sierra := .contract_class.json
compiled := .compiled_contract_class.json
store := ./account_sdk/artifacts/classes/

# Contract params for deploy.
test_pubkey = 0x1234
katana_0 = 0x517ececd29116499f4a1b64b094da79ba08dfd54a3edaa316134c41f8160973

generate_artifacts:
	cd ../controller-cairo && scarb build
	mkdir -p ${store}
	jq . ../controller-cairo/target/dev/controller_ControllerAccount${sierra} > ${store}controller.latest.contract_class.json
	cp ../controller-cairo/target/dev/controller_ControllerAccount${compiled} ${store}controller.latest.compiled_contract_class.json

setup-pre-commit:
	./bin/setup-pre-commit

lint:
	./bin/lint

lint-rust:
	./bin/rust-lint

lint-cairo:
	./bin/cairo-lint

lint-prettier:
	./bin/prettier-lint

lint-check:
	./bin/lint --check-only

clean:
	rm -rf ./target
