#!/usr/bin/env python3

from fractions import Fraction
from math import ceil
from math import comb


# The inverse of 2, i.e. 2^-1. To be used as a base in exponentiations
# representing probabilities.
INV2 = Fraction(1, 2)


# The probability of a false positive health test failure expressed as
# the negative logarithm of the *actual* probability. In simpler
# terms, the actual probability is:
#
# INV2 ** A
#
# It is simpler to keep this representation when computing the bound
# of the Repetition Count Test (below).
A = 40


# The estimated min-entropy per sample in bits. Min-entropy is the
# negative logarithm of the probability of the *most likely* outcome.
#
# We consider this estimate to be conservative.
H = 1


# The probability of the most likely outcome occurring in a given
# sample. This derives from the definition of min-entropy (see above).
P = INV2 ** H


# 4.4.1 Repetition Count Test
#
# The Repetition Count Test (RCT) detects catastrophic failures in the
# noise source when it becomes "stuck" generating a single value over
# many consecutive samples.
#
# The probability of generating C consecutive identical samples is:
#
# P^(C-1)
#
# Or equivalently:
#
# 2^(-H * (C-1))
#
# To keep this under our rate of acceptable false positives, we need
# to satisfy this inequality:
#
# 2^-A >= 2^(-H * (C-1))
#
# Taking the logarithm of both sides, we have:
#
# -A >= -H * (C-1)
#
# Solving for C, we have:
#
# (A / H) + 1 >= C
def repetition_count_bound():
    return 1 + ceil(Fraction(A, H))


# 4.4.2 Adaptive Proportion Test
#
# The Adaptive Proportion Test (APT) tries to detect more subtle noise
# source failures causing certain values to occur with unexpected
# frequency. It does this by taking a sample from the noise source and
# counting how many times the same sample occurs within a fixed-size
# window.


# The size of the window for non-binary alphabets for the APT.
W = 512


# The probability mass function measuring the probability of exactly k
# occurrences of a given value within the observation window of size
# W. We use the probability of the most likely event (as above).
#
# There are three terms:
#
# 1. The binomial coefficient of k, i.e. W-choose-k. Simply, how many
# ways are there to get exactly k outcomes given W chances.
#
# 2. The probability of each of those k events occurring.
#
# 3. The probability that the other W-k events have some other
# outcome.
def pmf(k):
    return comb(W, k) * P**k * (1 - P)**(W-k)


# The sum of probabilties of all possible counts of occurrences is 1.
assert sum(map(pmf, range(W+1))) == 1


# We want to find the minimal count of occurrences such that the
# cumulative probability of seeing *at least* that count of
# occurrences (but possibly more) is no more than our false
# positive threshold.
def adaptive_proportion_bound():
    # The list of probabilities for each of the possible counts of
    # occurrences.
    probs = [pmf(x) for x in range(W+1)]

    # The list of cumulative distributions for each of the possible
    # counts of occurrences.
    #
    # Whereas probs is a list of probabilities of *exactly* k
    # occurrences, this is a list of probabilities of *k or more*
    # occurrences.
    #
    # These are just sums of probabilities across a range of counts.
    dists = [sum(probs[x:]) for x in range(W+1)]

    # Because we have constructed dists as an ordered list of
    # cumulative probabilities, we can simply return the index of the
    # first value that is below our threshold.
    for i, d in enumerate(dists):
        if d <= INV2**A:
            return i


def main():
    print('Estimated min-entropy:', H)
    print('False positive rate: 2^-{}'.format(A))
    print('Repetition Count Test bound:', repetition_count_bound())
    print('Adaptive Proportion Test bound:', adaptive_proportion_bound())


if __name__ == '__main__':
    main()
