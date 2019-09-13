<!--
Copyright 2018 Thales UK Limited

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
-->

# p11tool [![Build Status](https://travis-ci.com/thales-e-security/p11tool.svg?branch=master)](https://travis-ci.com/thales-e-security/p11tool) [![Go Report Card](https://goreportcard.com/badge/github.com/thales-e-security/p11tool)](https://goreportcard.com/report/github.com/thales-e-security/p11tool)

A command line tool for interacting with [PKCS&nbsp;#11 tokens](https://en.wikipedia.org/wiki/PKCS_11). The intended 
audience is developers writing PKCS&nbsp;#11 applications who need to inspect objects, import test keys, delete 
generated keys, etc. (We wrote this tool to help with our own development projects).

## Installation

```
go get -u github.com/thales-e-security/p11tool
```

## Usage

Run `p11tool --help` to see available commands. Run `p11tool <command> --help` for help on individual commands.

Supported functionality:

- Print the attributes of all objects on the token. Optionally restricted to objects with a given label.
- Print all the mechanisms supported by a token.
- Delete all objects from the token. Optionally retain objects with the specified label(s).
- Import a plaintext AES key.
- Calculate a checksum for an AES key.

The token user PIN can be supplied as a command line argument or omitted, in which case it will be prompted for in the
terminal.

### AWS CloudHSM

CloudHSM produces a lot of noisy logs that make it impossible to read the outputs from p11tool. Here's how you can list the objects on a CloudHSM without seeing all the logs:

```bash
p11tool --lib /opt/cloudhsm/lib/libcloudhsm_pkcs11.so --pin <user>:<password> --token cavium list | grep -v "failed with error" | grep .
```

## Contributions

Contributions are very welcome. Either raise a pull request or open an issue to discuss a new feature. Here are some
of the things we'd like to add or improve:

- [ ] Printing nested templates (i.e. `CKA_WRAP_TEMPLATE` and `CKA_UNWRAP_TEMPLATE`).
- [x] Generating test keys (at least RSA and AES).
- [ ] Encryption, signing and verifying of test data using token keys.
- [ ] Reading of library path, token name and PIN from a config file.
