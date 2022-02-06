#!/bin/bash

wasm-pack build --release --target web -- --no-default-features --features "std"
