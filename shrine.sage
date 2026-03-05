#!/usr/bin/env sage
"""
SHRINE

SPHINCS+ selects a random FTS instance per signature.  SHRINE instead has
each device claim a random hypertree leaf at initialization and sign
sequentially through an inner unbalanced Merkle tree of PORS+FP instances
below that leaf.  This reduces the FTS collision domain from q_s (total
signatures) to u (device initializations).

Signature: PORS+FP sig + inner auth path (j+1 hashes) + outer hypertree proof.
"""

from sage.all import *
import os, sys

_dir = os.path.dirname(os.path.abspath(__file__))
_outer_name = __name__
__name__ = '_shrine_loading_'
load(os.path.join(_dir, "costs.sage"))
__name__ = _outer_name

# =============================================================================
# SHRINE signature size and verification time
# =============================================================================

def shrine_size(j, k, mmax, H_out, d, w):
    """SHRINE signature size in bytes for the j-th signature (0-indexed).

    R + PORS+FP(k + mmax hashes) + inner auth(j+1 hashes) + outer hypertree
    """
    l = compute_wots_l("W+C", w)
    h_prime = H_out // d
    pors_fp = (k + mmax) * hashbytes
    inner_auth = (j + 1) * hashbytes
    outer = d * (l * hashbytes + h_prime * hashbytes + counter_size)
    return randomness_size + pors_fp + inner_auth + outer


def shrine_vfy_time(j, H_out, d, a, k, w, swn, mmax):
    """SHRINE verification: standard W+C P+FP verification + j+1 inner hashes."""
    base = compute_verification_time(H_out, d, a, k, w, swn, "W+C_P+FP", mmax)
    return {
        'hashes': base['hashes'] + (j + 1),
        'compressions': base['compressions'] + (j + 1) * C_Th2,
    }

# =============================================================================
# Parameters
# =============================================================================

# SHRINE for Bitcoin: u <= 2^10 device initializations, sequential signing.
# Found via parameter sweep over (k, a, H_out, d): Pareto-optimal on the
# size-vs-signing-time frontier among configs with >= 128-bit security
# (see shrine_lib.sage --sweep).
SHRINE = {
    'u':     2**10,  # max device initializations
    'k':     10,     # PORS leaf indices per signature
    'a':     12,     # log2(leaves per PORS subtree); t = k * 2^a = 40960
    'H_out': 18,     # outer hypertree height (2^18 = 262144 outer leaves)
    'd':     2,      # hypertree layers (h' = 9 per layer)
    'w':     256,    # Winternitz parameter
    'swn':   2040,   # WOTS+C target chain sum S_{w,n}
}

# Stateless comparison: SPHINCS+ W+C P+FP at q_s = 2^20.
STATELESS = {
    'q_s': 20, 'k': 10, 'a': 15, 'h': 20, 'd': 2, 'w': 256, 'swn': 2040,
}

# =============================================================================
# Comparison
# =============================================================================

def main():
    s, sl = SHRINE, STATELESS

    # SHRINE metrics
    sec  = compute_security(s['u'], s['H_out'], s['k'], s['a'], "PORS+FP")
    sign = compute_signing_time(s['H_out'], s['d'], s['a'], s['k'],
                                s['w'], s['swn'], "W+C_P+FP")
    mmax = sign['mmax']
    size = shrine_size(0, s['k'], mmax, s['H_out'], s['d'], s['w'])
    vfy  = shrine_vfy_time(0, s['H_out'], s['d'], s['a'], s['k'],
                           s['w'], s['swn'], mmax)

    # Stateless SPHINCS+ metrics
    sl_sec  = compute_security(2**sl['q_s'], sl['h'], sl['k'], sl['a'], "PORS+FP")
    sl_sign = compute_signing_time(sl['h'], sl['d'], sl['a'], sl['k'],
                                   sl['w'], sl['swn'], "W+C_P+FP")
    sl_mmax = sl_sign['mmax']
    sl_size = compute_size(sl['h'], sl['d'], sl['a'], sl['k'], sl['w'],
                           "W+C_P+FP", sl_mmax)
    sl_vfy  = compute_verification_time(sl['h'], sl['d'], sl['a'], sl['k'],
                                        sl['w'], sl['swn'], "W+C_P+FP", sl_mmax)

    # --- Output ---
    W = 68
    print()
    print("=" * W)
    print(" SHRINE vs Stateless W+C P+FP 2^20 ".center(W, "="))
    print("=" * W)

    print()
    print("  SHRINE:     k=" + str(s['k']) + ", a=" + str(s['a']) +
          ", H_out=" + str(s['H_out']) + ", d=" + str(s['d']) +
          ", w=" + str(s['w']) + ", u=2^" + str(int(log(F(s['u']), 2))))
    print("  Stateless:  k=" + str(sl['k']) + ", a=" + str(sl['a']) +
          ", h=" + str(sl['h']) + ", d=" + str(sl['d']) +
          ", w=" + str(sl['w']) + ", q_s=2^" + str(sl['q_s']))

    print()
    hdr = "  " + "Metric".ljust(24) + "SHRINE".rjust(12) + "Stateless".rjust(12)
    print(hdr)
    print("  " + "-" * (W - 4))

    rows = [
        ("Security (bits)",       sec,                  sl_sec,                  "f1"),
        ("Size j=0 (bytes)",      size,                 sl_size,                 "d"),
        ("Signing (compr.)",      sign['compressions'], sl_sign['compressions'], "num"),
        ("Verification (compr.)", vfy['compressions'],  sl_vfy['compressions'],  "num"),
        ("mmax (auth nodes)",     mmax,                 sl_mmax,                 "d"),
    ]
    for label, v_s, v_sl, fmt in rows:
        if fmt == "f1":
            vs  = "{:.1f}".format(float(v_s))
            vsl = "{:.1f}".format(float(v_sl))
        elif fmt == "d":
            vs  = str(int(v_s))
            vsl = str(int(v_sl))
        else:
            vs  = format_num(v_s)
            vsl = format_num(v_sl)
        print("  " + label.ljust(24) + vs.rjust(12) + vsl.rjust(12))

    # Signature size at various j (inner auth path adds hashbytes per step)
    print()
    hdr = "  " + "j".ljust(24) + "SHRINE".rjust(12) + "Stateless".rjust(12)
    print(hdr)
    print("  " + "-" * (W - 4))

    for j in [0, 1, 4, 9, 27, 28, 100, 255]:
        sz = shrine_size(j, s['k'], mmax, s['H_out'], s['d'], s['w'])
        label = "Size j=" + str(int(j)) + " (bytes)"
        print("  " + label.ljust(24) + str(int(sz)).rjust(12) +
              str(int(sl_size)).rjust(12))

    print()


if sys.argv[0].endswith('shrine.sage') or \
   sys.argv[0].endswith('shrine.sage.py'):
    main()
