""" RSA Solving Module by polym / Tim https://github.com/abpolym """

import itertools, sys
from sage.all import *

"""
Simple Checks:

* Check GCD of a given Moduli Array. If any GCD of any combination of moduli is not 1, return dict with key modulus n_x and value primes [p_x, q_x]
"""

def simple_check(ns):
	ndpq = {}
	for (na, nb) in itertools.combinations(ns, 2):
		p = gcd(na, nb)
		if p == 1: continue
		qa = na/p
		qb = nb/p
		ndpq[na] = [p,qa]
		ndpq[nb] = [p,qb]
	return ndpq
"""
HASTAD's BROADCAST ATTACK
https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H.C3.A5stad.27s_broadcast_attack

Szenario:
	The public exponent e has to be small and the same for each public key.
	At least e moduli N and e ciphertexts C.
	The same message has been encrypted with different moduli N
Parameters:
	ns: Array of moduli N
	cs: Array of ciphertexts C
	e: Public Exponent
Returns:
	Decrypted Plaintext Message M
Note:
	Check gcd of each combination of moduli for != 1. If you find a GCD != 1, you can easily factor
"""
def hastad_broadcast(ns, cs, e):
	x = CRT_list(cs, ns)
	return x.nth_root(e)

"""
Fermat's Little Theorem Factoring Attack
http://www.enseignement.polytechnique.fr/informatique/profs/Francois.Morain/Master1/Crypto/projects/Weger02.pdf

Szenario:
	The difference between both primes p and q of the modulus N are close to each other.
Parameters:
	Modulus N
Returns:
	Primes P and Q of Modulus N
Note:
	Can be slow, add a timer to automatically abort on false given knowledge
"""
def little_fermat(N):
	if N <= 0: raise Exception("N is not an Integer (!=0)")
	if is_even(N): return [2, N/2]
	u = ceil(sqrt(N))
	while not is_square(pow(u,2) - N):
		u+=1
	v = sqrt(pow(u,2) - N)
	return [u - v, u + v]

"""
Common Modulus Attack
http://diamond.boisestate.edu/~liljanab/ISAS/course_materials/AttacksRSA.pdf

Szenario:
	Using the same modulus N, a plaintext message M is encrypted into different ciphertexts C_x using different public exponents e_x
Parameters:
	N: Common Modulus
	cs: Array of ciphertexts
	es: Array of public exponents
Returns:
	Decrypted Plaintext Message M
"""
def common_modulus(N, cs, es):
	for (e1, e2) in itertools.combinations(es, 2):
		assert e1!=e2
		if gcd(e1, e2) != 1: continue
		g, x, y = xgcd(e1, e2)
		if g!=1: raise Exception("WTF?")
		E = cs[es.index(e1)]
		if x < 0:
			E = inverse_mod(E, N)
			x *= -1
		F = cs[es.index(e2)]
		if y < 0:
			F = inverse_mod(F, N)
			y *= -1
		p1 = pow(E, x, N)
		p2 = pow(F, y, N)
		return (p1*p2) % N


"""
Wiener Attack
http://diamond.boisestate.edu/~liljanab/ISAS/course_materials/AttacksRSA.pdf
https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf

Szenario:
	
Parameters:
	N: Modulus
	e: Exponent
Returns:
	Primes of modulus N : P and Q as well as the private exponent d
"""
def wiener_attack(N, e):
	# https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/crypto/curious
	from utils.wiener_attack import wiener_attack as w
	p, q, d = w(N, e)
	return p, q, d


"""
Leaked Private Key Factoring Bruteforce Attack
http://crypto.stackexchange.com/questions/13113/how-can-i-find-the-prime-numbers-used-in-rsa

Szenario:
	The private key (N, d) is leaked and the public key (N, e) is known
Parameters:
	N: Modulus
	e: Public Exponent
	d: Private Exponent
	xbarrier: Barrier for small x -- the higher the slower, but most probable that you find a solution. Default 1024
	gbarrier: Barrier for "random" g -- the higher the slower, but most probable that you find a solution. Default 1024
Returns:
	Primes p and q of Modulus N
"""
def bruteforce_primes(N, e, d, xbarrier=1024, gbarrier=1024):
	# k = ed - 1 == 0 mod (p-1)(q-1)
	k = (e*d) - 1
	for x in range(xbarrier):
		for g in range(gbarrier):
			g = Integer(g)
			p = -1
			# in python: t = pow(g, k/(2**x), N)
			t = g.powermod(k/(2**x), N)
			p = gcd(N,t-1)
			if p!=-1 and p!=N and p!=1:
				q = N/p
				assert p*q==N
				return p,q

"""
Perfect Squared Attack
https://www.youtube.com/watch?v=tUUE41Gc5Q8

Szenario:
	The Modulus N is the difference of squares (perfect square). Meaning: N = a^2 - b^2 == (a-b)(a+b)
Parameters:
	N: Modulus
Returns:
	Primes p and q of Modulus N
"""
def perfect_square(N):
	# Find p^2 s.t. N + p^2 = q^2. If found, then N = p^2 - q^2 => (q-p)(q+p)
	(t, odd, i) = (None, 1, 0)
	while i != ceil(sqrt(N)):
		if i == 0: t = N
		(t, odd, i) = (t+odd, odd+2, i+1)
		if not t.is_square(): continue
		t = sqrt(t)
		(p, q) = (t-i, t+i)
		assert p*q == N
		return p,q
