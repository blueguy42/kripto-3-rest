const bn = require('bn.js');
const randomBytes = require('crypto').randomBytes

const curve = {
    p : uint256("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16),
    a : uint256(0),
    b : uint256(7),
    Gx : uint256("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
    Gy : uint256("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16),
    n : uint256("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
};

function uint256(x, base) {
  return new bn(x, base)
}

// Generate a random private key
async function getRandomPrivateKey() {
    return uint256(randomBytes(32)).umod(P).toString(16).padStart(64, '0');
}
  
// Compute the public key from the private key
async function getPublicKey(privateKey) {
    const G = [curve.Gx, curve.Gy, uint256(1)]
    let publicKey = pointMultiply(G, uint256(privateKey, 16), curve)
    const inv = publicKey[2].invm(curve.p)
    publicKey = [publicKey[0].mul(inv.mul(inv).umod(curve.p)).umod(curve.p), 
                publicKey[1].mul(inv.mul(inv.mul(inv).umod(curve.p)).umod(curve.p)).umod(curve.p)]
    // const pubX = uint256('5b75fd5f49e78191a45e1c9438644fe5d065ea98920c63e9eef86e151e99b809', 16)
    // const pubY = uint256('4eef2a826f1e6d13a4dde4e54800e8d282a2089a873072002e0a3a21eae5763a', 16)
    // const pk = pubX.toString(16).padStart(64, '0') + pubY.toString(16).padStart(64, '0');
    // const sig = sign("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    //       "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    // const valid = verify("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", sig, pk )
    // console.log(valid)
    return publicKey[0].toString(16).padStart(64, '0') + publicKey[1].toString(16).padStart(64, '0');
}

function mulmod(a, b, P) {
  return a.mul(b).umod(P)
}

function addmod(a, b, P) {
  return a.add(b).umod(P)
}

function invmod(a, P) {
  return a.invm(P)
}

function negmod(a, P) {
  return P.sub(a)
}

// Add two points on an elliptic curve
function pointAdd(point1, point2, curve) {
  if (point2[0] == 0 && point2[1] == 0 && point2[2] == 0) {
      return point1
  }

  let z2 = mulmod(point2[2], point2[2], curve.p)
  const u1 = mulmod(point1[0], z2, curve.p)
  const s1 = mulmod(point1[1], mulmod(z2, point2[2], curve.p), curve.p)
  z2 = mulmod(point1[2], point1[2], curve.p)
  let u2 = mulmod(point2[0], z2, curve.p)
  let s2 = mulmod(point2[1], mulmod(z2, point1[2], curve.p), curve.p)

  if (u1.eq(u2)) {
      if (!s1.eq(s2)) {
          return [_1, _1, _0]
      }
      else {
        const z2 = mulmod(point1[2], point1[2], curve.p)
        const m = addmod(mulmod(curve.a, mulmod(z2, z2, curve.p), curve.p), mulmod(uint256(3), mulmod(point1[0], point1[0], curve.p), curve.p), curve.p)
        const y2 = mulmod(point1[1], point1[1], curve.p)
        const s = mulmod(uint256(4), mulmod(point1[0], y2, curve.p), curve.p)
        const x = addmod(mulmod(m, m, curve.p), negmod(mulmod(s, uint256(2), curve.p), curve.p), curve.p)

        return [
            x,
            addmod(mulmod(m, addmod(s, negmod(x, curve.p), curve.p), curve.p), negmod(mulmod(uint256(8), mulmod(y2, y2, curve.p), curve.p), curve.p), curve.p),
            mulmod(uint256(2), mulmod(point1[1], point1[2], curve.p), curve.p)
        ]
      }
  }

  u2 = addmod(u2, negmod(u1, curve.p), curve.p)
  z2 = mulmod(u2, u2, curve.p)
  const t2 = mulmod(u1, z2, curve.p)
  z2 = mulmod(u2, z2, curve.p)
  s2 = addmod(s2, negmod(s1, curve.p), curve.p)
  const x = addmod(addmod(mulmod(s2, s2, curve.p), negmod(z2, curve.p), curve.p), negmod(mulmod(uint256(2), t2, curve.p), curve.p), curve.p)

  return [
      x,
      addmod(mulmod(s2, addmod(t2, negmod(x, curve.p), curve.p), curve.p), negmod(mulmod(s1, z2, curve.p), curve.p), curve.p),
      mulmod(u2, mulmod(point1[2], point2[2], curve.p), curve.p)
  ]
}

// Multiply a point by a scalar on an elliptic curve
function pointMultiply(point, scalar, curve) {
    let result = [uint256(0), uint256(0), uint256(0)];
    let addend = point;
  
    if (scalar == 0 || ((point[0] == 0) && (point[1] == 0)) ) {
        return result;
    }

    const d = scalar.clone()
    while (d != 0) {
        if (d.testn(0)) {
            result = pointAdd(addend, result, curve);
        }
        addend = pointAdd(addend, addend, curve);
        d.iushrn(1);
    }

    return result;
}

// Compute the signature
async function sign(hash, privateKey) {
    while (true) {
        const k = uint256(randomBytes(32), 16).umod(curve.p);
        const G = [curve.Gx, curve.Gy, uint256(1)];
        const r = pointMultiply(G, k, curve);
        if (r[0] == 0) continue;

        const e = uint256(hash, 16);
        const d = uint256(privateKey, 16);
        s = mulmod(k.invm(curve.n), addmod(e, mulmod(r[0], d, curve.n), curve.n), curve.n);
        if (s == 0) continue;
        if (s.testn(255)) continue;
        return {
          r: r[0].toString(16).padStart(64, '0'),
          s: s.toString(16).padStart(64, '0')
        };
    }
}

// Verify the signature
async function verify(hash, signature, publicKey) {
    const r = uint256(signature.r, 16);
    const s = uint256(signature.s, 16);
    const e = uint256(hash, 16);
    const Q = [uint256(publicKey.slice(0, 64), 16), uint256(publicKey.slice(64), 16), uint256(1)]

    // console.log(r)
    // console.log(s)

    // if (r <= 0 || r >= curve.n || s <= 0 || s >= curve.n) {
    //     return false;
    // }

    const w = s.invm(curve.n);
    const u1 = mulmod(e, w, curve.n)
    const u2 = mulmod(r, w, curve.n)
    const G = [curve.Gx, curve.Gy, uint256(1)]

    let P = pointAdd(pointMultiply(G, u1, curve), pointMultiply(Q, u2, curve), curve);
    const inv = P[2].invm(curve.p)
    P = [mulmod(P[0], mulmod(inv, inv, curve.p), curve.p),
         mulmod(P[1], mulmod(inv, mulmod(inv, inv, curve.p), curve.p), curve.p)]

    // console.log(r)
    // console.log(P[0])

    if (P === null) {
        return false;
    }

    return r.eq(P[0]);
}

module.exports = {
    getRandomPrivateKey,
    getPublicKey,
    sign,
    verify
}
