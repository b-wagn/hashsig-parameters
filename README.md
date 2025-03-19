# Parameters for Hash-Based Signatures

This repository contains Python scripts to estimate efficiency and set parameters of hash-based signatures.

## Generating Tables

You can generate a table showing parameters and resulting signature sizes and verifier hashing complexity using
```
    python3 table.py
```

## Setting Lifetimes
By default, the script will assume a key lifetime of `L = 2^18` slots. You can change this by adding `--log-lifetime x` if you want key lifetime `L=2^x`.

## Optional Flags
For a reduced version of the table, you can add the `--reduced` flag, and if you want to print in LaTeX, you can add the `--latex` flag.

## Selecting the Hash Function

By default, it is assumed that Poseidon2 is used, but the table can also be generated under the assumption that SHA3-256 is used.
For that, add the `--sha` flag.