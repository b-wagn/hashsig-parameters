# Script to produce a table comparing schemes

from typing import List
from tabulate import tabulate
import argparse

from parameters.common import (
    IncomparableEncoding,
    life_time_in_days,
    life_time_in_years,
    signature_size,
)
from parameters.poseidon import (
    bytes_per_field_element,
    hash_len_poseidon,
    parameter_len_poseidon,
    target_sum_encoding_poseidon,
    winternitz_encoding_poseidon,
    verifier_hashing as verifier_hashing_poseidon,
)
from parameters.sha import (
    hash_len_sha,
    parameter_len_sha,
    target_sum_encoding_sha,
    verifier_hashing as verifier_hashing_sha,
    winternitz_encoding_sha,
)

WORD_SIZE = 32 * 8
KIB = 1024 * 8
SECONDS_PER_SLOT = 4

LOG_FIELD_SIZE = 31

# -------------------------------------------------------------------#
#           Assembling Schemes, Tables, and Exporting Data           #
# -------------------------------------------------------------------#


def format_hash_pairs_poseidon(hashing):
    """
    Takes a list of tuples (width, frequency) and turns it into a
    more readable string.
    """
    # sort
    sorted_pairs = sorted(hashing, key=lambda x: x[0])
    # format each pair, then join them
    formatted_parts = [f"{count} x Perm({integer})" for integer, count in sorted_pairs]
    result = ", ".join(formatted_parts)

    return result


def table_row_poseidon(
    log_field_size: int,
    log_lifetime: int,
    encoding: IncomparableEncoding,
    is_reduced: bool,
    is_single_permutation: bool
) -> List[str]:
    """
    Creates a row for the table, given a scheme (assuming Poseidon).
    """
    # Determine parameter and hash lengths
    parameter_len = parameter_len_poseidon(
        log_field_size, log_lifetime, encoding.num_chunks, encoding.chunk_size
    )
    hash_len = hash_len_poseidon(
        log_field_size, log_lifetime, encoding.num_chunks, encoding.chunk_size
    )

    # Determine signature size and verifier hashing
    signature_field_elements = signature_size(log_lifetime, hash_len, encoding)
    signature = (
        signature_field_elements * bytes_per_field_element(log_field_size) * 8 / KIB
    )
    hashing_avg = format_hash_pairs_poseidon(
        verifier_hashing_poseidon(
            log_field_size, log_lifetime, parameter_len, hash_len, encoding, False, is_single_permutation
        )
    )
    hashing_wc = format_hash_pairs_poseidon(
        verifier_hashing_poseidon(
            log_field_size, log_lifetime, parameter_len, hash_len, encoding, True, is_single_permutation
        )
    )

    # Assemble the row
    if is_reduced:
        row = [
            encoding.name,
            encoding.chunk_size,
            encoding.comment,
            signature,
            hashing_avg,
            hashing_wc,
        ]
    else:
        row = [
            encoding.name,
            encoding.chunk_size,
            encoding.comment,
            encoding.num_chunks,
            parameter_len,
            encoding.rand_len,
            encoding.mes_hash_len,
            hash_len,
            signature,
            hashing_avg,
            hashing_wc,
        ]
    return row


def table_row_sha(
    log_lifetime: int, encoding: IncomparableEncoding, is_reduced: bool
) -> List[str]:
    """
    Creates a row for the table, given a scheme (assuming SHA3-256).
    """
    # Determine parameter and hash lengths
    parameter_len = parameter_len_sha(
        log_lifetime, encoding.num_chunks, encoding.chunk_size
    )
    hash_len = hash_len_sha(log_lifetime, encoding.num_chunks, encoding.chunk_size)

    # Determine signature size and verifier hashing
    signature = signature_size(log_lifetime, hash_len, encoding) / KIB
    hashing_avg = (
        verifier_hashing_sha(log_lifetime, parameter_len, hash_len, encoding, False)
        / WORD_SIZE
    )
    hashing_wc = (
        verifier_hashing_sha(log_lifetime, parameter_len, hash_len, encoding, True)
        / WORD_SIZE
    )

    # Assemble the row
    if is_reduced:
        row = [
            encoding.name,
            encoding.chunk_size,
            encoding.comment,
            signature,
            hashing_avg,
            hashing_wc,
        ]
    else:
        row = [
            encoding.name,
            encoding.chunk_size,
            encoding.comment,
            encoding.num_chunks,
            parameter_len,
            encoding.rand_len,
            encoding.mes_hash_len,
            hash_len,
            signature,
            hashing_avg,
            hashing_wc,
        ]
    return row


log_lifetime_range = [18, 20]
w_range = [1, 2, 4, 8]
target_sum_offset_range = [1, 1.1]

# Create the parser
parser = argparse.ArgumentParser(description="Check for flags")

# Add the --reduced flag
parser.add_argument("--reduced", action="store_true", help="Enable reduced mode")
parser.add_argument("--latex", action="store_true", help="Enable latex mode")
parser.add_argument("--sha", action="store_true", help="Enable SHA3-256 mode")
parser.add_argument("--single", action="store_true", help="Use the same permutation width for everything")

# Parse the arguments
args = parser.parse_args()

# Check if flags are present
is_reduced = args.reduced
is_latex = args.latex
is_sha = args.sha
is_single_permutation = args.single

# Set headers based on flags
if is_sha:
    headers = (
        [
            "Encoding",
            "Chunk Size [bits]",
            "Comment",
            "Signature [KiB]",
            "Hashing av [words]",
            "Hashing wc [words]",
        ]
        if is_reduced
        else [
            "Encoding",
            "Chunk Size [bits]",
            "Comment",
            "Num Chunks",
            "Par Len [bits]",
            "Rand Len [bits]",
            "Mes Hash Len [bits]",
            "Hash Len [bits]",
            "Signature [KiB]",
            "Hashing av [words]",
            "Hashing wc [words]",
        ]
    )
else:
    headers = (
        [
            "Encoding",
            "Chunk Size [bits]",
            "Comment",
            "Signature [KiB]",
            "Hashing av",
            "Hashing wc",
        ]
        if is_reduced
        else [
            "Encoding",
            "Chunk Size [bits]",
            "Comment",
            "Num Chunks",
            "Par Len [FE]",
            "Rand Len [FE]",
            "Mes Hash Len [bits]",
            "Hash Len [FE]",
            "Signature [KiB]",
            "Hashing av",
            "Hashing wc",
        ]
    )

# Notes
print(
    "Note: in the following tables, the parameter delta takes the following role: "
    "the target sum is set to delta * exp_sum, where exp_sum is the expected sum if all chunks were uniform."
)
print("Note: 1 Word = 32 Byte")
if not is_sha:
    print("Note: FE = Field Element")
    print(f"Note: Log of field size is {LOG_FIELD_SIZE}")

# Generate tables
for log_lifetime in log_lifetime_range:
    years = life_time_in_years(log_lifetime, SECONDS_PER_SLOT)
    days = life_time_in_days(log_lifetime, SECONDS_PER_SLOT)

    print(f"\nWith 4 second slots: L = 2^{log_lifetime}, {years} years = {days} days")

    table = []

    for w in w_range:
        if is_sha:
            encoding = winternitz_encoding_sha(log_lifetime, w)
            table.append(table_row_sha(log_lifetime, encoding, is_reduced))
        else:
            encoding = winternitz_encoding_poseidon(LOG_FIELD_SIZE, log_lifetime, w)
            table.append(
                table_row_poseidon(LOG_FIELD_SIZE, log_lifetime, encoding, is_reduced, is_single_permutation)
            )

    for w in w_range:
        for target_sum_offset in target_sum_offset_range:
            if is_sha:
                encoding = target_sum_encoding_sha(log_lifetime, w, target_sum_offset)
                table.append(table_row_sha(log_lifetime, encoding, is_reduced))
            else:
                encoding = target_sum_encoding_poseidon(
                    LOG_FIELD_SIZE, log_lifetime, w, target_sum_offset
                )
                table.append(
                    table_row_poseidon(
                        LOG_FIELD_SIZE, log_lifetime, encoding, is_reduced, is_single_permutation
                    )
                )

    rounded_table = [
        [round(cell, 2) if isinstance(cell, (int, float)) else cell for cell in row]
        for row in table
    ]

    print(
        tabulate(
            rounded_table, headers=headers, tablefmt="latex" if is_latex else "pretty"
        )
    )
    print("\n" + "-" * 80 + "\n")
