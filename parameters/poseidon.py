# This module contains functions to determine parameters
# for the generalized XMSS scheme, with different encodings.
# Everything assuming Poseidon2 is used for hashing.

from collections import Counter
import math
from typing import List, Tuple

from lower_bounds import (
    SECURITY_LEVEL_QUANTUM,
    lower_bound_hash_len,
    lower_bound_message_hash_len_target_sum,
    lower_bound_message_hash_len_winternitz,
    lower_bound_parameter_len,
    lower_bound_rand_len_target_sum,
    lower_bound_rand_len_winternitz,
)
from parameters.common import (
    MESSAGE_LEN,
    IncomparableEncoding,
    integer_to_base,
    winternitz_average_sum,
)

# -------------------------------------------------------------------#
#                 Bits, Bytes and Field Elements                     #
# -------------------------------------------------------------------#


def bytes_per_field_element(log_field_size) -> int:
    """
    Returns the number of bytes to encode a field element.
    """
    # assume k <= log p < k+1. Then 2^k <= p <= 2^{k+1}
    # this means we need k+1 bits to represent a field element
    bits = math.floor(log_field_size) + 1
    bytes = math.ceil(bits / 8)
    return bytes


def field_elements_to_encode(log_field_size, input_len) -> int:
    """
    Returns the number of field elements we need if
    we want to encode a message of length input_len bits.
    I.e., it returns chi such that p^chi > 2^input_len
    """

    # The number of field elements chi is the minimum chi such that p^chi > 2^input_len
    # or equivalently, chi log p > input_len
    res = math.ceil(input_len / log_field_size)

    # we want strict inequality, so maybe we need to add one
    if input_len % log_field_size == 0:
        res += 1

    return res


def field_elements_to_encode_message(log_field_size) -> int:
    """
    Returns the number of field elements we need if
    we want to encode a message.
    """
    return field_elements_to_encode(log_field_size, MESSAGE_LEN)


def field_elements_to_encode_tweak(log_field_size) -> int:
    """
    Returns the number of field elements we need if
    we want to encode a tweak (including l_p, l_t, l_mes, l_rnd, T).
    """
    tweak_len_bit = 4 * 8 + (8 + 3 * 32)
    return field_elements_to_encode(log_field_size, tweak_len_bit)


# -------------------------------------------------------------------#
#                        Permutation Widths                          #
# -------------------------------------------------------------------#


def round_to_valid_width(width: int) -> int:
    """
    rounds a desired permutation width up to a valid width.
    A valid width for Poseidon2 is a multiple of 4.
    """
    return math.ceil(width / 4) * 4


def permutation_width_message_hash(
    parameter_len: int, tweak_encoding_len: int, message_len_fe: int, rand_len: int
) -> int:
    """
    Returns the permutation width that the message hash
    uses internally. The message hash is Decode(PoseidonCompress(...))
    and PoseidonCompress internally runs the Poseidon Permutation with
    a certain width t (Field^t -> Field^t). The function outputs t.
    """
    return round_to_valid_width(
        parameter_len + tweak_encoding_len + message_len_fe + rand_len
    )


def permutation_width_chain_hash(
    parameter_len: int, tweak_encoding_len: int, hash_len: int
) -> int:
    """
    Returns the permutation width that the chain hash
    uses internally. The chain hash is PoseidonCompress(...)
    and PoseidonCompress internally runs the Poseidon Permutation with
    a certain width t (Field^t -> Field^t). The function outputs t.
    """
    return round_to_valid_width(parameter_len + tweak_encoding_len + hash_len)


def permutation_width_tree_hash(
    parameter_len: int, tweak_encoding_len: int, hash_len: int
) -> int:
    """
    Returns the permutation width that the tree hash
    uses internally. The tree hash is PoseidonCompress(...)
    and PoseidonCompress internally runs the Poseidon Permutation with
    a certain width t (Field^t -> Field^t). The function outputs t.
    """
    return round_to_valid_width(parameter_len + tweak_encoding_len + 2 * hash_len)


def permutation_widths_leaf_hash(
    parameter_len: int, tweak_encoding_len: int, hash_len: int, num_chains: int
) -> List[int]:
    """
    Returns the list of permutation widths that the leaf
    hash uses internally. The leaf hash uses the Sponge mode,
    and so multiple different invocations of the Poseidon
    permutation are used.
    """

    # initially, we use a call to PoseidonCompress that calls
    # the permutation with width hash_len
    widths = [round_to_valid_width(hash_len)]

    # now, we loop for s iterations, and always do a permutation of
    # width 3 * hash_len. So, we first need to determine s.
    par_tweak_mes_len = parameter_len + tweak_encoding_len + num_chains * hash_len
    s = math.ceil(par_tweak_mes_len / (2 * hash_len)) * 2 * hash_len
    widths += s * [round_to_valid_width(3 * hash_len)]

    return widths


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
    tweak_encoding_len = field_elements_to_encode_tweak(log_field_size)
    internal_hashing = permutation_width_message_hash(
        parameter_len, tweak_encoding_len, message_len_fe, rand_len
    )

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
    tweak_encoding_len = field_elements_to_encode_tweak(log_field_size)
    internal_hashing = permutation_width_message_hash(
        parameter_len, tweak_encoding_len, message_len_fe, rand_len
    )

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
    # additional constraint for the Sponge mode
    lower_bound_unruh = math.ceil(3 * SECURITY_LEVEL_QUANTUM / log_field_size)
    return max(lower_bound_unruh, math.ceil(lower_bound / log_field_size))


# -------------------------------------------------------------------#
#                             Hashing                                #
# -------------------------------------------------------------------#


def merkle_verify_hashing(
    log_field_size: int, log_lifetime: int, hash_len: int, parameter_len: int
) -> int:
    """
    Returns the hash complexity to verify a Merkle path given the root and
    the leaf. The Merkle tree is assumed to have 2 ** log_lifetime many leafs,
    and each inner node is hash_len long. We also hash the public parameters.

    Note: the output is a list of pairs (width, count), and each such pair
    indicates that the Poseidon permutation of width `width` is called `count`
    many times.

    Note: this assumes that hash_len and parameter_len are given in the unit
    "number of field elements".

    Note: this does not include compressing the leaf, i.e., the leaf is
    already assumed to be of length hash_len.
    """

    # one hash per layer of the tree
    num_hashes = log_lifetime
    tweak_encoding_len = field_elements_to_encode_tweak(log_field_size)
    one_hash = permutation_width_tree_hash(parameter_len, tweak_encoding_len, hash_len)
    return num_hashes * [one_hash]


def verifier_hashing(
    log_field_size: int,
    log_lifetime: int,
    parameter_len: int,
    hash_len: int,
    encoding: IncomparableEncoding,
    worst_case: bool,
) -> List[Tuple[int, int]]:
    """
    Returns the hash complexity of verification, given lifetime, output length
    of the tweakable hash, and encoding.

    Note: the output is a list of pairs (width, count), and each such pair
    indicates that the Poseidon permutation of width `width` is called `count`
    many times.

    Note: this assumes that hash_len and parameter_len are given in the unit
    "number of field elements", and that encoding.internal_hashing gives the
    permutation width of the internal hashing call of the encoding.

    Note: Switch between worst-case and average-case using the flag worst_case.
    """
    hashing = []

    # Encode the message, which might involve some hashing
    hashing += [encoding.internal_hashing]

    # For the chains: determine how many steps are needed in total
    chain_steps_signer = encoding.min_sum if worst_case else encoding.avg_sum
    base = 2**encoding.chunk_size
    chain_steps_total = encoding.num_chunks * (base - 1)
    chain_steps_verifier = chain_steps_total - chain_steps_signer

    # For each step, hash the parameters, tweak and one hash
    tweak_encoding_len = field_elements_to_encode_tweak(log_field_size)
    one_chain_hash = permutation_width_chain_hash(
        parameter_len, tweak_encoding_len, hash_len
    )
    hashing += int(chain_steps_verifier) * [one_chain_hash]

    # Now, we hash the chain ends to get the leaf
    hashing += permutation_widths_leaf_hash(
        parameter_len, tweak_encoding_len, hash_len, encoding.num_chunks
    )

    # Verify the Merkle path
    hashing += merkle_verify_hashing(
        log_field_size, log_lifetime, hash_len, parameter_len
    )

    # Now, hashing contains all invocations separately, but we want to
    # group them (compute a histogram in some sense)
    return list(Counter(hashing).items())
