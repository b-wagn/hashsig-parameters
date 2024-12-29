# This module contains functions to determine parameters
# for the generalized XMSS scheme, with different encodings.

import math
import random
from dataclasses import dataclass

SECURITY_LEVEL_CLASSICAL = 128
SECURITY_LEVEL_QUANTUM = 64
MESSAGE_LEN = 256

# certain lengths are rounded up to bytes
# e.g., the output length of the hash output
GRANULARITY = 8

def round_up_to_granularity(s):
    return math.ceil(s / GRANULARITY) * GRANULARITY

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
    comment : str


# -------------------------------------------------------------------#
#                        Basic Winternitz                            #
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
    base = 2 ** chunk_size
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


    pass

def make_winternitz_encoding(log_lifetime: int, chunk_size: int) -> IncomparableEncoding:

    # randomness length
    rand_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + log_lifetime + 1)
    rand_len_quantum = math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + math.log2(3)) + log_lifetime)
    rand_len = round_up_to_granularity(max(rand_len_classical, rand_len_quantum))

    # minimum output length of message hash
    min_kappa_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + 1)
    min_kappa_quantum = math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + 1) + 3)
    min_kappa = round_up_to_granularity(max(min_kappa_classical, min_kappa_quantum))
    mes_hash_len = min_kappa

    # number of chunks for the message part
    num_chunks_message = math.ceil(min_kappa / chunk_size)

    # number of chunks for the checksum part
    base = 2 ** chunk_size
    max_checksum = num_chunks_message * (base - 1)
    num_chunks_checksum = 1 + math.ceil(math.log(max_checksum, base))

    # total number of chunks
    num_chunks = num_chunks_message + num_chunks_checksum

    # internal hashing: we hash the parameters, the message, and the randomness
    parameter_len = determine_parameter_len(log_lifetime, num_chunks, chunk_size)
    internal_hashing = parameter_len + rand_len + MESSAGE_LEN

    # minimum sum is zero for message and everything for checksum
    min_sum = 0 + max_checksum

    # average sum: determine via simulation
    avg_sum = winternitz_average_sum(chunk_size, num_chunks_message)

    # meta information
    name = "W"
    comment = "num_chunks_checksum = "+ str(num_chunks_checksum)

    return IncomparableEncoding(
        rand_len,
        num_chunks,
        chunk_size,
        mes_hash_len,
        internal_hashing,
        min_sum,
        avg_sum,
        name,
        comment
    )


# -------------------------------------------------------------------#
#                      Target Sum Winternitz                         #
# -------------------------------------------------------------------#

def make_target_sum_encoding(log_lifetime: int, chunk_size: int, target_sum_offset: float) -> IncomparableEncoding:

    # assume at most 4096 tries
    log_K = 12

    # randomness length
    rand_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + log_lifetime + log_K + 1)
    rand_len_quantum = math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + math.log2(3) + log_K) + log_lifetime)
    rand_len = round_up_to_granularity(max(rand_len_classical, rand_len_quantum))

    # minimum output length of message hash
    min_msg_hash_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + 1)
    min_msg_hash_len_quantum =  math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + 1) + 3)
    min_msg_hash_len = round_up_to_granularity(max(min_msg_hash_len_classical, min_msg_hash_len_quantum))

    # want that number of chunks * chunk_size >= min_msg_hash_len
    num_chunks = math.ceil(min_msg_hash_len / chunk_size)

    # actual hash length needs to be num_chunks * chunk_size
    mes_hash_len = num_chunks * chunk_size

    # internal hashing: we hash the parameters, the message, and the randomness
    parameter_len = determine_parameter_len(log_lifetime, num_chunks, chunk_size)
    internal_hashing = parameter_len + rand_len + MESSAGE_LEN

    # target sum as a multiplicative offset from the expectation
    expected_sum = num_chunks * (2 ** chunk_size - 1)/2
    target_sum = math.ceil(target_sum_offset * expected_sum)

    min_sum = target_sum
    avg_sum = target_sum

    # meta information
    name = "TSW"
    comment = "offset = " + str(target_sum_offset) + ", target sum = " + str(target_sum)

    return IncomparableEncoding(
        rand_len,
        num_chunks,
        chunk_size,
        mes_hash_len,
        internal_hashing,
        min_sum,
        avg_sum,
        name,
        comment
    )

# -------------------------------------------------------------------#
#                            Lifetime                                #
# -------------------------------------------------------------------#


def life_time_in_years(log_lifetime: int, seconds_per_slot: int):
    """
    Returns the number of years a key can be used for signing
    2 ** log_lifetime many epochs (= leafs in Merkle tree).
    """
    life_time_seconds = seconds_per_slot * (2 ** log_lifetime)
    life_time_hours = life_time_seconds / 3600
    life_time_days = life_time_hours / 24
    life_time_years = life_time_days / 365
    return life_time_years

# -------------------------------------------------------------------#
#                          Signature Size                            #
# -------------------------------------------------------------------#


def merkle_path_size(log_lifetime: int, hash_len: int) -> int:
    """
    Returns the size of a Merkle path in bits.
    The Merkle tree is assumed to have 2 ** log_lifetime many
    leafs, and each inner node is hash_length bits long.
    Note: The size does not include the leaf itself.
    """
    num_hashes = log_lifetime
    return num_hashes * hash_len


def signature_size(log_lifetime: int, hash_len: int, encoding: IncomparableEncoding) -> int:
    """
    Returns the size of a signature (in bits), given the lifetime, the
    output length of the tweakable hash, and the incomparable encoding.
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


def merkle_verify_hashing(log_lifetime: int, hash_len: int, parameter_len: int) -> int:
    """
    Returns the number of bits that need to be hashed to verify
    a Merkle path given the root and the leaf.
    The Merkle tree is assumed to have 2 ** log_lifetime many
    leafs, and each inner node is hash_length bits long.
    For each hash invocation, we also need to hash the public parameters.
    """
    num_hashes = log_lifetime
    return num_hashes * (parameter_len + 2 * hash_len)


def verifier_hashing(
    log_lifetime: int,
    parameter_len: int,
    hash_len: int,
    encoding: IncomparableEncoding,
    worst_case: bool
) -> int:
    """
    Returns the worst-case number of bits that need to be hashed
    during verification, given lifetime, output length of tweakable
    hash, and encoding. We do not count tweaks, as they can be hardcoded.
    Switch between worst-case and average-case using the boolean flag worst_case.
    """
    hashing = 0

    # Encode the message, which might involve some hashing
    hashing += encoding.internal_hashing

    # For the chains: determine how many steps are needed in total
    chain_steps_signer = encoding.min_sum if worst_case else encoding.avg_sum
    base = 2 ** encoding.chunk_size
    chain_steps_total = encoding.num_chunks * (base - 1)
    chain_steps_verifier = chain_steps_total - chain_steps_signer

    # For each step, hash the parameters and one hash
    hashing += chain_steps_verifier * (parameter_len + hash_len)

    # Verify the Merkle path
    hashing += merkle_verify_hashing(log_lifetime, hash_len, parameter_len)

    return hashing

# -------------------------------------------------------------------#
#                Setting Parameters from Security Level              #
# -------------------------------------------------------------------#


def determine_parameter_len(log_lifetime: int, num_chains: int, chunk_size: int) -> int:
    """
    Determines the parameter length based on the security level.
    As we need to account for some security loss, we need to take
    the lifetime and the number and length of chains into account.
    """
    min_par_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + 3)
    min_par_len_quantum = math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + 2) + 5)
    return round_up_to_granularity(max(min_par_len_classical, min_par_len_quantum))


def determine_hash_len(log_lifetime: int, num_chains: int, chunk_size: int) -> int:
    """
    Determines the hash output length based on the security level.
    As we need to account for some security loss, we need to take
    the lifetime and the number and length of chains into account.
    """
    min_hash_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + 2*chunk_size + log_lifetime + math.log2(num_chains))
    min_hash_len_quantum = math.ceil(2* (SECURITY_LEVEL_QUANTUM + math.log2(5) + 2*chunk_size + log_lifetime + math.log2(num_chains) + math.log2(12)))
    return round_up_to_granularity(max(min_hash_len_classical, min_hash_len_quantum))