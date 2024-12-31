# Script to produce a table comparing schemes

from typing import List
from tabulate import tabulate
import argparse

from parameters import *

WORD_SIZE = 32 * 8
KIB = 1024 * 8
SECONDS_PER_SLOT = 4

# -------------------------------------------------------------------#
#           Assembling Schemes, Tables, and Exporting Data           #
# -------------------------------------------------------------------#

def make_table_row(log_lifetime : int, encoding : IncomparableEncoding, is_reduced: bool) -> List[str]:
    """
        creates a row for the table, given a scheme
    """

    # determine parameter and hash lengths
    parameter_len = determine_parameter_len(log_lifetime, encoding.num_chunks, encoding.chunk_size)
    hash_len = determine_hash_len(log_lifetime, encoding.num_chunks, encoding.chunk_size)

    # determine signature size and verifier hashing
    signature = signature_size(log_lifetime, hash_len, encoding) / KIB
    hashing_avg = verifier_hashing(log_lifetime, parameter_len, hash_len, encoding, False) / WORD_SIZE
    hashing_wc = verifier_hashing(log_lifetime, parameter_len, hash_len, encoding, True) / WORD_SIZE

    # assemble the row
    row = []

    if is_reduced:
        row = [encoding.name, encoding.chunk_size, encoding.comment, signature, hashing_avg, hashing_wc]
    else:
        row = [encoding.name, encoding.chunk_size, encoding.comment, encoding.num_chunks, parameter_len, encoding.rand_len, encoding.mes_hash_len, hash_len, signature, hashing_avg, hashing_wc]

    return row


log_lifetime_range = [18, 20]
w_range = [1, 2, 4, 8]
target_sum_offset_range = [1, 1.1]



# Create the parser
parser = argparse.ArgumentParser(description="Check for flags")

# Add the --reduced flag
parser.add_argument('--reduced', action='store_true', help='Enable reduced mode')
parser.add_argument('--latex', action='store_true', help='Enable latex mode')

# Parse the arguments
args = parser.parse_args()

# Check if flags are present
is_reduced = args.reduced
is_latex = args.latex


if is_reduced:
    headers = [
        "Encoding",
        "Chunk Size w",
        "Comment",
        "Signature",
        "Hashing-av",
        "Hashing-wc"
    ]
else:
    headers = [
        "Encoding",
        "Chunk Size w",
        "Comment",
        "Num Chunks v",
        "Par Len log|P|",
        "Rand Len l_rnd",
        "Mes Hash Len kappa",
        "Hash Len n",
        "Signature",
        "Hashing-av",
        "Hashing-wc"
    ]


print("Note: in the following tables, the parameter delta takes the following role: the target sum is set to delta * exp_sum, where exp_sum is the expected sum if all chunks were uniform.")

for log_lifetime in log_lifetime_range:
    # how long would it take with this lifetime?
    years = life_time_in_years(log_lifetime, SECONDS_PER_SLOT)
    days = life_time_in_days(log_lifetime, SECONDS_PER_SLOT)

    print("")
    print("With 4 second slots: L = 2^" + str(log_lifetime) + ", " + str(years) + " years = " + str(days) + " days")

    # create a new table for that lifetime
    table = []

    # data to print some string that can be pasted into LaTeX later
    latex_data_type = []
    latex_data_number = []
    latex_data_legend = []

    # first, the Winternitz part
    for w in w_range:
        encoding = make_winternitz_encoding(log_lifetime, w)
        table.append(make_table_row(log_lifetime, encoding, is_reduced))

    # second, the Target Sum Winternitz part
    for w in w_range:
        for target_sum_offset in target_sum_offset_range:
            encoding = make_target_sum_encoding(log_lifetime, w, target_sum_offset)
            table.append(make_table_row(log_lifetime, encoding, is_reduced))

    # round numbers in the table
    rounded_table = [[round(cell, 2) if isinstance(cell, (int, float)) else cell for cell in row] for row in table]

    # print the table
    if is_latex:
        print(tabulate(rounded_table, headers=headers, tablefmt="latex"))
    else:
        print(tabulate(rounded_table, headers=headers, tablefmt="pretty"))

    print("")
    print("-" * 80)
    print("")
    print("")
