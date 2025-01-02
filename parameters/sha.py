# This module contains functions to determine parameters
# for the generalized XMSS scheme, with different encodings.
# Everything assuming SHA-256 is used for hashing.

import math

from lower_bounds import (
    lower_bound_hash_len,
    lower_bound_message_hash_len_target_sum,
    lower_bound_message_hash_len_winternitz,
    lower_bound_parameter_len,
    lower_bound_rand_len_target_sum,
    lower_bound_rand_len_winternitz,
)
from parameters.common import MESSAGE_LEN, IncomparableEncoding, winternitz_average_sum


def round_up_to_bytes(s):
    """
    round a number of bits to the next multiple of 8
    """
    return math.ceil(s / 8) * 8


def winternitz_encoding_sha(log_lifetime: int, chunk_size: int) -> IncomparableEncoding:
    """
    Returns the Winternitz encoding when SHA256 is used for message hashing.
    The result uses bits as its unit, i.e., rand_len, mes_hash_len, internal hashing
    are all given in bits.
    """

    # randomness length
    rand_len = round_up_to_bytes(lower_bound_rand_len_winternitz(log_lifetime))

    # minimum output length of message hash
    min_kappa = round_up_to_bytes(lower_bound_message_hash_len_winternitz())
    mes_hash_len = min_kappa

    # number of chunks for the message part
    num_chunks_message = math.ceil(min_kappa / chunk_size)

    # number of chunks for the checksum part
    base = 2**chunk_size
    max_checksum = num_chunks_message * (base - 1)
    num_chunks_checksum = 1 + math.ceil(math.log(max_checksum, base))

    # total number of chunks
    num_chunks = num_chunks_message + num_chunks_checksum

    # internal hashing: we hash the parameters, the message, and the randomness
    parameter_len = parameter_len_sha(log_lifetime, num_chunks, chunk_size)
    internal_hashing = parameter_len + rand_len + MESSAGE_LEN

    # minimum sum is zero for message and everything for checksum
    min_sum = 0 + max_checksum

    # average sum: determine via simulation
    avg_sum = winternitz_average_sum(chunk_size, num_chunks_message)

    # meta information
    name = "W"
    comment = "num chunks checksum = " + str(num_chunks_checksum)

    return IncomparableEncoding(
        rand_len,
        num_chunks,
        chunk_size,
        mes_hash_len,
        internal_hashing,
        min_sum,
        avg_sum,
        name,
        comment,
    )


# -------------------------------------------------------------------#
#                      Target Sum Winternitz                         #
# -------------------------------------------------------------------#


def target_sum_encoding_sha(
    log_lifetime: int, chunk_size: int, target_sum_offset: float
) -> IncomparableEncoding:
    """
    Returns the target sum encoding when SHA256 is used for message hashing.
    The result uses bits as its unit, i.e., rand_len, mes_hash_len, internal hashing
    are all given in bits.
    """

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
    parameter_len = parameter_len_sha(log_lifetime, num_chunks, chunk_size)
    internal_hashing = parameter_len + rand_len + MESSAGE_LEN

    # target sum as a multiplicative offset from the expectation
    base = 2**chunk_size
    expected_sum = num_chunks * (base - 1) / 2
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
        comment,
    )


# -------------------------------------------------------------------#
#                Setting Parameters from Security Level              #
# -------------------------------------------------------------------#


def parameter_len_sha(log_lifetime: int, num_chains: int, chunk_size: int) -> int:
    """
    Determines the parameter length based on the security level.
    As we need to account for some security loss, we need to take
    the lifetime and the number and length of chains into account.
    Note: The result is given in bits.
    """
    lower_bound = lower_bound_parameter_len(log_lifetime, num_chains, chunk_size)
    return round_up_to_bytes(lower_bound)


def hash_len_sha(log_lifetime: int, num_chains: int, chunk_size: int) -> int:
    """
    Determines the hash output length based on the security level.
    As we need to account for some security loss, we need to take
    the lifetime and the number and length of chains into account.
    Note: The result is given in bits.
    """
    lower_bound = lower_bound_hash_len(log_lifetime, num_chains, chunk_size)
    return round_up_to_bytes(lower_bound)
