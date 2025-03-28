#------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#------------------------------------------------------------------------------
SHELL := /bin/bash
.PHONY: reference_values build test clean
default: test doc

RV_OUTPUT_FILE := out/reference-values.json
GIT_COMMIT := $(shell git log --pretty=tformat:"%h" -n1 .)

reference-values:
	mkdir -p out
	@scripts/reference_values.sh > $(RV_OUTPUT_FILE)

build: reference-values
	@scripts/build.sh

test: build
	@scripts/test.sh

doc: reference-values
	node scripts/doc_gen.js `pwd`/$(RV_OUTPUT_FILE) $(GIT_COMMIT) > out/td-integrity.html

clean:
	rm -rf out
