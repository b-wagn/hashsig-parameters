# Parameters for Hash-Based Signatures

This repository contains Python scripts to estimate efficiency and set parameters of hash-based signatures.

## Generating Tables

You can generate a table showing parameters and resulting signature sizes and verifier hashing complexity using
```
    python3 table.py
```

For a reduced version of the table, you can add the `--reduced` flag, and if you want to print in LaTeX, you can add the `--latex` flag.