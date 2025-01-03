# This module contains functions to determine parameters
# for the generalized XMSS scheme, with different encodings.
# Everything assuming Poseidon2 is used for hashing.

import math

from lower_bounds import (
    lower_bound_hash_len,
    lower_bound_message_hash_len_target_sum,
    lower_bound_message_hash_len_winternitz,
    lower_bound_parameter_len,
    lower_bound_rand_len_target_sum,
    lower_bound_rand_len_winternitz,
)
from parameters.common import MESSAGE_LEN, IncomparableEncoding, integer_to_base, winternitz_average_sum


def bytes_per_field_element(log_field_size) -> int:
    """
    Returns the number of bytes to encode a field element.
    """
    # assume k <= log p < k+1. Then 2^k <= p <= 2^{k+1}
    # this means we need k+1 bits to represent a field element
    bits = math.floor(log_field_size) + 1
    bytes = math.ceil(bits / 8)
    return bytes


def field_elements_to_encode_message(log_field_size) -> int:
    """
    Returns the number of field elements we need if
    we want to encode a message.
    """

    # The number of field elements chi is the minimum chi such that p^chi > 2^MESSAGE_LEN
    # or equivalently, chi log p > MESSAGE_LEN
    res = math.ceil(MESSAGE_LEN / log_field_size)

    # we want strict inequality, so maybe we need to add one
    if MESSAGE_LEN % log_field_size == 0:
        res += 1

    return res


# -------------------------------------------------------------------#
#                        Basic Winternitz                            #
# -------------------------------------------------------------------#


def winternitz_encoding_poseidon(
    log_field_size: int, log_lifetime: int, chunk_size: int
) -> IncomparableEncoding:
    """
    Returns the Winternitz encoding when Poseidon2 is used for message hashing.
    The result uses "number of field elements" as its unit. Precisely, variables
    rand_len, mes_hash_len, and internal hashing are all given in that unit.
    Therefore, we need to take as input the logarithm of the field size.
    """

    # randomness length (in "number of field elements")
    rand_len = math.ceil(lower_bound_rand_len_winternitz(log_lifetime) / log_field_size)

    # now, we want to determine the number of chunks.
    # for that, we first assume the message is hashed to a vector of
    # field elements (enough to be secure)
    mes_hash_len = math.ceil(lower_bound_message_hash_len_winternitz() / log_field_size)
    # then, we need to choose the number of chunks such that we can
    # encode the vector of field elements into num_chunks_message * chunk_size
    # many bits. This encoding needs to be injective.
    num_chunks_message = math.ceil(mes_hash_len * log_field_size / chunk_size)

    # number of chunks for the checksum part
    base = 2**chunk_size
    max_checksum = num_chunks_message * (base - 1)
    num_chunks_checksum = 1 + math.floor(math.log(max_checksum, base))

    # total number of chunks
    num_chunks = num_chunks_message + num_chunks_checksum

    # internal hashing: we hash the parameters, the message, and the randomness
    # for the message, we first need to encode it as field elements.
    message_len_fe = field_elements_to_encode_message(log_field_size)
    parameter_len = parameter_len_poseidon(
        log_field_size, log_lifetime, num_chunks, chunk_size
    )
    internal_hashing = parameter_len + rand_len + message_len_fe

    # minimum sum is zero for message and everything for checksum
    # so we first represent the max_checksum in the base and sum
    # up the digits. Then, we compute the min_sum.
    max_checksum_sum = sum(integer_to_base(max_checksum, base))
    min_sum = 0 + max_checksum_sum

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


def target_sum_encoding_poseidon(
    log_field_size: int, log_lifetime: int, chunk_size: int, target_sum_offset: float
) -> IncomparableEncoding:
    """
    Returns the target sum encoding when Poseidon2 is used for message hashing.
    The result uses "number of field elements" as its unit. Precisely, variables
    rand_len, mes_hash_len, and internal hashing are all given in that unit.
    Therefore, we need to take as input the logarithm of the field size.
    """

    # assume at most 4096 tries
    log_K = 12

    # randomness length(in "number of field elements")
    rand_len = math.ceil(
        lower_bound_rand_len_target_sum(log_lifetime, log_K) / log_field_size
    )

    # now, we want to determine the number of chunks.
    # for that, we first assume the message is hashed to a vector of
    # field elements (enough to be secure)
    mes_hash_len = math.ceil(lower_bound_message_hash_len_target_sum() / log_field_size)
    # then, we need to choose the number of chunks such that we can
    # encode the vector of field elements into num_chunks * chunk_size
    # many bits. This encoding needs to be injective.
    num_chunks = math.ceil(mes_hash_len * log_field_size / chunk_size)

    # internal hashing: we hash the parameters, the message, and the randomness
    # for the message, we first need to encode it as field elements.
    message_len_fe = field_elements_to_encode_message(log_field_size)
    parameter_len = parameter_len_poseidon(
        log_field_size, log_lifetime, num_chunks, chunk_size
    )
    internal_hashing = parameter_len + rand_len + message_len_fe

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


def parameter_len_poseidon(
    log_field_size: int, log_lifetime: int, num_chains: int, chunk_size: int
) -> int:
    """
    Determines the parameter length based on the security level.
    As we need to account for some security loss, we need to take
    the lifetime and the number and length of chains into account.
    Note: the result is given in "number of field elements".
    Therefore, we need to know the logarithm of the field size.
    """
    lower_bound = lower_bound_parameter_len(log_lifetime, num_chains, chunk_size)
    return math.ceil(lower_bound / log_field_size)


def hash_len_poseidon(
    log_field_size: int, log_lifetime: int, num_chains: int, chunk_size: int
) -> int:
    """
    Determines the hash output length based on the security level.
    As we need to account for some security loss, we need to take
    the lifetime and the number and length of chains into account.
    Note: the result is given in "number of field elements".
    Therefore, we need to know the logarithm of the field size.
    """
    lower_bound = lower_bound_hash_len(log_lifetime, num_chains, chunk_size)
    return math.ceil(lower_bound / log_field_size)
