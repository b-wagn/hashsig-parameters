# This module contains functions to determine parameters
# for the generalized XMSS scheme, with different encodings.
# The functions in this module are independent of the hash function
# that is used in the scheme.

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
    comment : str

# -------------------------------------------------------------------#
#                         Lifetime to Time                           #
# -------------------------------------------------------------------#

def life_time_in_days(log_lifetime: int, seconds_per_slot: int):
    """
    Returns the number of days a key can be used for signing
    2 ** log_lifetime many epochs (= leafs in Merkle tree).
    """
    life_time_seconds = seconds_per_slot * (2 ** log_lifetime)
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


def signature_size(log_lifetime: int, hash_len: int, encoding: IncomparableEncoding) -> int:
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
