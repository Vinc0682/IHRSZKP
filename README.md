# IHRSZKP (Identity Hiding Ring Signature Zero Knowledge Proof)

This is an proof-of-concept implementation of a new zero knowledge proof allowing
to verify that the proofer is part of a group while neither the verifier nor
proofer who the other members of the group are.

**WARNING: This implementation should not be used in a production environment 
(or any environment with critical data) since it is var-time and may have crucial bugs I didn't find!**

## Possible use case

Imagine this scenario:

 - Alice wants to grant Bob, Cloe and Dave access to some data she stores at Erik
 - Alice trusts that Erik only grants access to the people her algorithm allowed
 - However, it is known that Erik collects as much data as possible so Alice want to tell Erik as little as possible
 - Cloe and Dave shouldn't know that the other one has access to the data, but it is fine for both of them to know that there are to more people having access to the data.
 
IHRSZKP will mask the public keys of Bob, Cloe and Dave in a way allowing them to still sign a ring signature without knowing
who the other's masked public keys belong to. Erik only gets to see the masked public keys and the signatures which won't
reveal which group member signed them.

## How it works

The ZKP can be separated into 3 phases:

- Issuing: Alice generates the data for Erik needed to run the ZKP
- Proofing: Bob, Cloe, or Dave sign a random challenge from Erik with his masked key to proof that he's a part of the ring.
- Verifying: Erik verifies the given signature

### Issuing

To securely outsource the verifying to Erik, Alice first generate a random private curve25519 key
`m` and calculates it's corresponding public key `M = mG`. She then calculates a verify-key for each public key `P` of 
each recipient / group member using `Vi = mPi`. Alice then sends `(M,V)` to Erik. All the public keys are now masked and
unmasking them requires knowledge of `m`, however it's very hard for Erik to recover `m` from `M` under
the elliptic curve discrete logarithm assumption.

### Proofing

To proof that he's a part of the group, Dave requests `M, V` and a random challenge `C` from Erik.
The challenge shouldn't be repeated to prevent replay attacks. As this ZKP is based on a signature algorithm,
`C` also may be used to sign some data instead. (But keep the replay attack in mind.)

Having all the data needed to fulfill the proof, Dave first calculates his masked key by running
`xM`, where `x` is his private key, and looks up it's index `j` in `V`. He then generates an array with `n` random numbers
and an empty list `X` with the size of `n` and a random `a`.

Having done that, Dave calculates the signature in the following way:

`Xj = aM`, `c(j+1) = H(C, Xj)`

`X(j+1) = s(j+1)M + c(j+1)V(j+1)`, `c(j+2) = H(C, X(j+1))`

`X(j+2) = s(j+2)M + c(j+2)V(j+2)`, `c(j+3) = H(C, X(j+2))`

...

`X(j-1) = s(j-1)M + c(j-1)V(j-1)`, `cj = H(C, X(j-1))`

`sj = a - cj * x`, this leads to `Xj = aM = sjM + cjxM = sjM + cjVj`

Dave then finally sends `(s,X)` to Erik who will then verify the signature.

### Verification

To do so, Erik reconstructs `c0` using `c0 = H(C, Xn)` and then recreates `X'0 = s0M + c0V0` and compares it to `X0`.
If they differ, he reports that the signature is invalid and then aborts. If not, he reconstructs `c1` to rebuild `X'1`
and compare it to `X1` etc. The signature is valid when all `X` match with their reconstructions.

## Aimed security targets

These claims are not binding, but I think they may be true since that's what I aimed for when creating the ZKP:

 - Forging a proof without knowing a private key should be hard under the discrete logarithm assumption. The proof given
 in the Monero RingCT-whitepaper may be applied to this algorithm.
 - Finding a private key should be hard, I guess the Monero RingCT proof can be applied again since the masking just
 transfers the base-point.
 - Unmasking should be hard, when `m` is not known. To do so, one would either have to break the ECDLP oder ECDH problem,
 so the algorithm should be on the safe side.
