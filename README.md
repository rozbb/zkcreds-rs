<h1 align="center">zkcreds-rs</h1>
<p align="center">
    <a href="https://github.com/rozbb/zkcreds-rs/blob/main/LICENSE-APACHE"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
    <a href="https://github.com/rozbb/zkcreds-rs/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <!--<a href="https://deps.rs/repo/github/rozbb/zkcreds-rs"><img src="https://deps.rs/repo/github/rozbb/zkcreds-rs/status.svg"></a>-->
</p>

A cryptographic library for designing anonymous credential systems in a flexible, issuer-agnostic, and efficient manner using general-purpose zero-knowledge proofs. This code accompanies the zk-creds paper [here](https://eprint.iacr.org/2022/878).

While the core library is written in Rust, this repository also includes an associated Python wrapper module for some of the higher-level interfaces. See [`src/lib.rs`](src/lib.rs), [`python-examples`](python-examples), and Web Demo below for more details.

## Development

For an overview of this library and usage snippets, see the wiki [here](XXX).

## Web Demo

With Rust v1.48+ and Python v3.7+ installed:

```bash
$ cd zkcreds-rs
# Install appropriate `python3.Xvenv` package...
# Configure Python virtual environment
$ python3 -m venv .env
$ source .env/bin/activate
$ pip install maturin

# Compile Rust binaries and intall as Python (PyO3) bindings
$ maturin develop
# Local webserver provides a high-level demo
$ python3 python-examples/web-demo.py
```

Interact with the demo to get an idea for how arbitrary attribute fields can be formulated into a credential, and how this credential can be issued and subsequently shown without revealing any more than the fact that it satisfies the given criteria.

## Benchmarks

You can run benchmarks using `cargo bench`. This will produce `criterion` benchmarks in `target/criterion/`. It will also create `proof_sizes.csv`, which records proof sizes across various benchmarks.

The passport benchmarks will error if you do not provide a valid (USA only, currently) passport dump.

### Passport benches

In order to run the benchmarks in `bench/passport`, you need to have a JSON dump of a passport. You can create this from your own US passport by installing the Android app [here](XXX link to passport github) (a prebuilt debug APK can be found in the root directory). Once you have your passport dump in the clipboard, send it to yourself, put it in a file named `passport_dump.json`, and move it to this repo in `benches/passport/passport_dump.json`.

## License

 This library is distributed under either of the following licenses:
 
 * Apache License v2.0 ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT License ([LICENSE-MIT](LICENSE-MIT))
 
Unless explicitly stated otherwise, any contribution made to this library shall be dual-licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

## Authors

* Michael Rosenberg - micro@cs.umd.edu
* Jacob White - white570@purdue.edu
