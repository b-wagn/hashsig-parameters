# This module contains functions to determine parameters
# for the generalized XMSS scheme, with different encodings.
# The functions in this module are independent of the hash function
# that is used in the scheme.

import math
import random
from dataclasses import dataclass

SECURITY_LEVEL_CLASSICAL = 128
SECURITY_LEVEL_QUANTUM = 64
MESSAGE_LEN = 256


# -------------------------------------------------------------------#
#                   Incomparable Encoding Schemes                    #
# -------------------------------------------------------------------#


@dataclass
class IncomparableEncoding:
    """
    Data class to represent an incomparable encoding scheme.
    It is specified by a randomness length, and parameters
    w (chunk size) and v (number of chunks of codeword).

    Internal hashing refers to how many bits need to be hashed
    in one invocation of evaluating the encoding scheme.
    Min_sum refers to a lower bound on the sum of chunks, which
    is relevant for determining worst case hashing.
    avg_sum is the average sum of the chunks.
    comment is used for tables
    """

    rand_len: int
    num_chunks: int
    chunk_size: int
    mes_hash_len: int
    internal_hashing: int
    min_sum: int
    avg_sum: int
    name: str
    comment: str


# -------------------------------------------------------------------#
#                      Winternitz - Average Sum                      #
# -------------------------------------------------------------------#


def winternitz_average_sum(chunk_size: int, num_chunks_message) -> float:
    """
    Estimates the average sum of chunks for the Winternitz encoding
    assuming a random message hash. This is done by simulation over
    a number of runs and averaging.
    """
    num_runs = 2000
    avg_sum = 0.0

    # some information we need about lengths of checksum etc.
    base = 2**chunk_size
    max_checksum = num_chunks_message * (base - 1)
    num_chunks_checksum = 1 + math.ceil(math.log(max_checksum, base))

    for _ in range(num_runs):
        # sample a random message hash by sampling
        # each chunk independently.
        chunks_message = random.choices(range(base), k=num_chunks_message)
        sum_message = sum(chunks_message)

        checksum = max_checksum - sum_message
        # now we need to represent the checksum in the right
        # base to get chunks of the checksum
        chunks_checksum = []
        for _ in range(num_chunks_checksum):
            chunks_checksum.append(checksum % base)
            checksum //= base
        sum_checksum = sum(chunks_checksum)

        # compute the total sum and aggregate into average
        total_sum = sum_message + sum_checksum
        avg_sum += total_sum

    avg_sum /= num_runs
    return avg_sum


# -------------------------------------------------------------------#
#                         Lifetime to Time                           #
# -------------------------------------------------------------------#


def life_time_in_days(log_lifetime: int, seconds_per_slot: int):
    """
    Returns the number of days a key can be used for signing
    2 ** log_lifetime many epochs (= leafs in Merkle tree).
    """
    life_time_seconds = seconds_per_slot * (2**log_lifetime)
    life_time_hours = life_time_seconds / 3600
    life_time_days = life_time_hours / 24
    return life_time_days


def life_time_in_years(log_lifetime: int, seconds_per_slot: int):
    """
    Returns the number of years a key can be used for signing
    2 ** log_lifetime many epochs (= leafs in Merkle tree).
    """
    life_time_days = life_time_in_days(log_lifetime, seconds_per_slot)
    life_time_years = life_time_days / 365
    return life_time_years


# -------------------------------------------------------------------#
#                          Signature Size                            #
# -------------------------------------------------------------------#


def merkle_path_size(log_lifetime: int, hash_len: int) -> int:
    """
    Returns the size of a Merkle path.
    The Merkle tree is assumed to have 2 ** log_lifetime many
    leafs, and each inner node is hash_length long.
    Note: The size does not include the leaf itself.
    Note: If hash_len is given in some unit, e.g., bits or field
    elements, then the result of this function also has this unit
    """
    num_hashes = log_lifetime
    return num_hashes * hash_len


def signature_size(
    log_lifetime: int, hash_len: int, encoding: IncomparableEncoding
) -> int:
    """
    Returns the size of a signature, given the lifetime, the output length
    of the tweakable hash, and the incomparable encoding.
    Note: hash_len and encoding.rand_len must be given in the same unit U, e.g., bits
    Note: the result of this function is then also in unit U
    """
    signature_size = 0

    # The signature contains randomness for the incomparable encoding
    signature_size += encoding.rand_len

    # The signature contains the Merkle path
    signature_size += merkle_path_size(log_lifetime, hash_len)

    # For each chain, the signature contains one hash
    # There is one chain per chunk
    signature_size += encoding.num_chunks * hash_len

    return signature_size



# -------------------------------------------------------------------#
#                             Hashing                                #
# -------------------------------------------------------------------#


def merkle_verify_hashing(
    log_lifetime: int, hash_len: int, parameter_len: int
) -> int:
    """
    Returns the hash complexity to verify a Merkle path given the root and
    the leaf. The Merkle tree is assumed to have 2 ** log_lifetime many leafs,
    and each inner node is hash_len long. We also hash the public parameters.

    Note: this assumes that hash_len and parameter_len are given in the same
    unit (e.g., bits, or field elements), and the resulting hash complexity
    is given in the same unit.

    Note: this does not include compressing the leaf, i.e., the leaf is
    already assumed to be of length hash_len.
    """
    num_hashes = log_lifetime
    return num_hashes * (parameter_len + 2 * hash_len)

def verifier_hashing(
    log_lifetime: int,
    parameter_len: int,
    hash_len: int,
    encoding: IncomparableEncoding,
    worst_case: bool,
) -> int:
    """
    Returns the hash complexity of verification, given lifetime, output length
    of the tweakable hash, and encoding.

    Note: this assumes that hash_len, parameter_len, encoding.internal_hashing
    all have the same unit (e.g., bits, or field elements), and the resulting
    hash complexity is given in the same unit.

    Note: We do not count tweaks, as they can be hardcoded.
    Note: Switch between worst-case and average-case using the flag worst_case.
    """
    hashing = 0

    # Encode the message, which might involve some hashing
    hashing += encoding.internal_hashing

    # For the chains: determine how many steps are needed in total
    chain_steps_signer = encoding.min_sum if worst_case else encoding.avg_sum
    base = 2**encoding.chunk_size
    chain_steps_total = encoding.num_chunks * (base - 1)
    chain_steps_verifier = chain_steps_total - chain_steps_signer

    # For each step, hash the parameters and one hash
    hashing += chain_steps_verifier * (parameter_len + hash_len)

    # Now, we hash the chain ends to get the leaf
    hashing += parameter_len + encoding.num_chunks * hash_len

    # Verify the Merkle path
    hashing += merkle_verify_hashing(log_lifetime, hash_len, parameter_len)

    return hashing