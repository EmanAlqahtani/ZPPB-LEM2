"""
Copyright (c) 2016, Kevin Lewi

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

"""
Tests the correctness of the implementation of IPE and two-input functional
encryption.
"""

# Path hack
import sys, os
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))

import random
from fhipe.fhipe import ipe

def test_ipe():
  """
  Runs a test on IPE for toy parameters.
  """

  n = 10
  M = 20
  x = [random.randint(0, M) for i in range(n)]
  y = [random.randint(0, M) for i in range(n)]

  checkprod = sum(map(lambda i: x[i] * y[i], range(n)))
  print(x)

  (pp, sk) = ipe.setup(n)
  skx = ipe.keygen(sk, x)
  print(skx)
  cty = ipe.encrypt(sk, y)
  prod = ipe.decrypt(pp, skx, cty, M*M*n)
  assert prod == checkprod, "Failed test_ipe"
  print(prod)

test_ipe()
