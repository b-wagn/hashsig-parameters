# Parameters for Hash-Based Signatures

This repository contains Python scripts to estimate efficiency and set parameters of hash-based signatures.

## Generating Tables

You can generate a table showing parameters and resulting signature sizes and verifier hashing complexity using
```
    python3 table.py
```

## Optional Flags
For a reduced version of the table, you can add the `--reduced` flag, and if you want to print in LaTeX, you can add the `--latex` flag.
Another option is to add the flag `--single`. If you add this flag, the script will assume that we implement every Poseidon permutation call using the same permutation width (the maximum over all required widths).

## Selecting the Hash Function

By default, it is assumed that Poseidon2 is used, but the table can also be generated under the assumption that SHA3-256 is used.
For that, add the `--sha` flag.