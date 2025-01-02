# This module contains functions to determine parameters
# for the generalized XMSS scheme, with different encodings.
# Everything assuming SHA-256 is used for hashing.

import math
import random

from lower_bounds import lower_bound_hash_len, lower_bound_message_hash_len_target_sum, lower_bound_message_hash_len_winternitz, lower_bound_parameter_len, lower_bound_rand_len_target_sum, lower_bound_rand_len_winternitz
from parameters.common import MESSAGE_LEN, IncomparableEncoding

def round_up_to_bytes(s):
    """
    round a number of bits to the next multiple of 8
    """
    return math.ceil(s / 8) * 8


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
    rand_len = round_up_to_bytes(lower_bound_rand_len_winternitz(log_lifetime))

    # minimum output length of message hash
    min_kappa = round_up_to_bytes(lower_bound_message_hash_len_winternitz())
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
    comment = "num chunks checksum = "+ str(num_chunks_checksum)

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
    rand_len = round_up_to_bytes(lower_bound_rand_len_target_sum(log_lifetime, log_K))

    # minimum output length of message hash
    min_msg_hash_len = round_up_to_bytes(lower_bound_message_hash_len_target_sum())

    # want that number of chunks * chunk_size >= min_msg_hash_len
    num_chunks = math.ceil(min_msg_hash_len / chunk_size)

    # actual hash length needs to be num_chunks * chunk_size
    mes_hash_len = num_chunks * chunk_size

    # internal hashing: we hash the parameters, the message, and the randomness
    parameter_len = determine_parameter_len(log_lifetime, num_chunks, chunk_size)
    internal_hashing = parameter_len + rand_len + MESSAGE_LEN

    # target sum as a multiplicative offset from the expectation
    base = 2 ** chunk_size
    expected_sum = num_chunks * (base - 1)/2
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
#                Setting Parameters from Security Level              #
# -------------------------------------------------------------------#


def determine_parameter_len(log_lifetime: int, num_chains: int, chunk_size: int) -> int:
    """
    Determines the parameter length based on the security level.
    As we need to account for some security loss, we need to take
    the lifetime and the number and length of chains into account.
    """
    lower_bound = lower_bound_parameter_len(log_lifetime, num_chains, chunk_size)
    return round_up_to_bytes(lower_bound)


def determine_hash_len(log_lifetime: int, num_chains: int, chunk_size: int) -> int:
    """
    Determines the hash output length based on the security level.
    As we need to account for some security loss, we need to take
    the lifetime and the number and length of chains into account.
    """
    lower_bound = lower_bound_hash_len(log_lifetime, num_chains, chunk_size)
    return round_up_to_bytes(lower_bound)


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

    # Now, we hash the chain ends to get the leaf
    hashing += parameter_len + encoding.num_chunks * hash_len

    # Verify the Merkle path
    hashing += merkle_verify_hashing(log_lifetime, hash_len, parameter_len)

    return hashing
