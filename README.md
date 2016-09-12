[![Build Status](https://travis-ci.org/blockchain-certificates/merkle-proofs.svg?branch=master)](https://travis-ci.org/blockchain-certificates/merkle-proofs)
[![PyPI version](https://badge.fury.io/py/merkle-proofs.svg)](https://badge.fury.io/py/merkle-proofs)

# About

Python library allowing creation of Merkle trees and output receipts
in a format consistent with the [chainpoint](https://github.com/chainpoint) v2 standard.

Also allows validation of a Merkle receipt.

This was developed in support of the [Blockchain Certificates](http://certificates.media.mit.edu/) project.
It supports only a subset of the Chainpoint v2 standard.


## Using the pypi package

The most common way to use this is to add the [latest cert-verifier pypi package](https://badge.fury.io/py/merkle-proofs) to your project dependencies. 


## Running the CLI locally

1. Ensure you have an python environment. [Recommendations](https://github.com/blockchain-certificates/developer-common-docs/blob/master/virtualenv.md)

2. Git clone the repository and change to the directory

  ```bash
  git clone https://github.com/blockchain-certificates/merkle-proofs.git && cd merkle-proofs
  ```

3. Run merkle-proofs setup

  ```bash
  pip install .
  ```

## Unit tests

This project uses tox to validate against several python environments.

```
tox
```




