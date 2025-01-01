# This module contains functions to determine lower bounds on
# certain parameters and sets based on a given security level

import math

SECURITY_LEVEL_CLASSICAL = 128
SECURITY_LEVEL_QUANTUM = 64


def lower_bound_parameter_len(log_lifetime: int, num_chains: int, chunk_size: int) -> int:
    """
    Determines a lower bound on log|P|, where P is the set of parameters,
    based on the security level. As we need to account for some security loss,
    we take the lifetime and the number and length of chains into account.
    """
    min_par_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + 3)
    min_par_len_quantum = math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + 2) + 5)
    return max(min_par_len_classical, min_par_len_quantum)


def lower_bound_hash_len(log_lifetime: int, num_chains: int, chunk_size: int) -> int:
    """
    Determines a lower bound on log|H|, where H is the output domain of the hash,
    based on the security level. As we need to account for some security loss,
    we need to take the lifetime and the number and length of chains into account.
    """
    min_hash_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + 2*chunk_size + log_lifetime + math.log2(num_chains))
    min_hash_len_quantum = math.ceil(2* (SECURITY_LEVEL_QUANTUM + math.log2(5) + 2*chunk_size + log_lifetime + math.log2(num_chains) + math.log2(12)))
    return max(min_hash_len_classical, min_hash_len_quantum)

def lower_bound_rand_len_winternitz(log_lifetime: int) -> int:
    """
    Determines a lower bound on log|R| for the Winternitz encoding, where R is the
    randomness domain of the encoding scheme. The bound depends on the lifetime and
    the repetition parameter K.
    """
    rand_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + log_lifetime + 1)
    rand_len_quantum = math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + math.log2(3)) + log_lifetime)
    return max(rand_len_classical, rand_len_quantum)

def lower_bound_message_hash_len_winternitz() -> int:
    """
    Determines a lower bound on the output length (in bits) of the message hash for the
    the Winternitz encoding. It must be that num_chunks_message * chunk_size is at least that.
    """
    min_kappa_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + 1)
    min_kappa_quantum = math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + 1) + 3)
    return max(min_kappa_classical, min_kappa_quantum)

def lower_bound_rand_len_target_sum(log_lifetime: int, log_K: int) -> int:
    """
    Determines a lower bound on log|R| for the target sum encoding, where R is the
    randomness domain of the encoding scheme. The bound depends on the lifetime and
    the repetition parameter K.
    """
    rand_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + log_lifetime + log_K + 1)
    rand_len_quantum = math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + math.log2(3) + log_K) + log_lifetime)
    return max(rand_len_classical, rand_len_quantum)

def lower_bound_message_hash_len_target_sum() -> int:
    """
    Determines a lower bound on the output length (in bits) of the message hash for
    the target sum encoding. It must be that num_chunks * chunk_size is at least that.
    """
    min_msg_hash_len_classical = math.ceil(SECURITY_LEVEL_CLASSICAL + math.log2(5) + 1)
    min_msg_hash_len_quantum =  math.ceil(2 * (SECURITY_LEVEL_QUANTUM + math.log2(5) + 1) + 3)
    return max(min_msg_hash_len_classical, min_msg_hash_len_quantum)