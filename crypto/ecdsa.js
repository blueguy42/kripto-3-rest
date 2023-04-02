const curve = {
    p : 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    a : 0x0000000000000000000000000000000000000000000000000000000000000000n,
    b : 0x0000000000000000000000000000000000000000000000000000000000000007n,
    Gx : 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    Gy : 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    n : 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
};

var getMultiplier = e => 10n ** BigInt(e)

function multiply(a, b) {
    let multiplier = getMultiplier(a["dec"]) * getMultiplier(b["dec"])
    let ab;
    if ((a["int"] > b["int"]) && (a["int"].toString().length > multiplier.toString().length)) {
        ab = a["int"] / multiplier * b["int"]
    } else if ((b["int"] > a["int"]) && (b["int"].toString().length > multiplier.toString().length)) {
        ab = b["int"] / multiplier * a["int"]
    } else if ((b["int"].toString().length + a["int"].toString().length) > multiplier.toString().length) {
        ab = a["int"] * b["int"] / multiplier
    } else {
        let missing = multiplier.toString().length - (b["int"].toString().length + a["int"].toString().length) + 1
        ab = a["int"] * b["int"] * getMultiplier(missing) / multiplier
        // ab = Number(ab) / Number(getMultiplier(missing))
        ab = Math.floor(ab / getMultiplier(missing))
    }
    return ab
}

function toInt(e) {
    let eArray = e.split(".")
    let pair = [];
    pair["int"] = BigInt(eArray[0] + (eArray[1] ? eArray[1] : ""))
    pair["dec"] = (eArray[1] ? eArray[1].length : 0)
    return pair
}

// Check if a private key is valid
function isValidPrivateKey(privateKey) {
    const maxPrivateKey = curve.n - 1n;
    return BigInt(privateKey) > 0n && BigInt(privateKey) <= maxPrivateKey;
}

// Generate a random private key
async function getRandomPrivateKey() {
    let privateKey;
    do {
        privateKey = multiply(toInt(Math.random().toString()), toInt(curve.n.toString()));
    } while (!isValidPrivateKey(privateKey));
    return privateKey.toString(16).padStart(64, '0');
}
  
// Compute the public key from the private key
async function getPublicKey(privateKey) {
    const d = BigInt('0x' + privateKey);
    const G = { x: curve.Gx, y: curve.Gy };
    const Q = pointMultiply(G, d, curve);

    return Q.x.toString(16).padStart(64, '0') + Q.y.toString(16).padStart(64, '0');
}

// Compute the modular inverse of a number
function modInverse(a, m) {
    let [x, y] = [0n, 1n];
    let [lastX, lastY] = [1n, 0n];
    let [q, r] = [];
  
    while (a !== 0n) {
      q = m / a;
      r = m % a;
      [m, a] = [a, r];
      [x, lastX] = [lastX - q * x, x];
      [y, lastY] = [lastY - q * y, y];
    }
  
    return lastX < 0n ? lastX + m : lastX;
}

// Add two points on an elliptic curve
function pointAdd(point1, point2, curve) {
    if (point1 === null) {
      return point2;
    }
  
    if (point2 === null) {
      return point1;
    }
  
    if (point1.x === point2.x && point1.y === point2.y) {
      const slope = (3n * point1.x ** 2n + curve.a) * modInverse(2n * point1.y, curve.p);
      const x = (((slope ** 2n - 2n * point1.x) % curve.p) + curve.p) % curve.p;
      const y = (((slope * (point1.x - x) - point1.y) % curve.p) + curve.p) % curve.p;
      return { x, y };
    }
  
    if (point1.x === point2.x && point1.y === curve.p - point2.y) {
      return null;
    }
  
    const slope = (point2.y - point1.y) * modInverse(point2.x - point1.x, curve.p);
    const x = (((slope ** 2n - point1.x - point2.x) % curve.p) + curve.p) % curve.p;
    const y = (((slope * (point1.x - x) - point1.y) % curve.p ) + curve.p) % curve.p;
  
    return { x, y };
}

// Multiply a point by a scalar on an elliptic curve
function pointMultiply(point, scalar, curve) {
    let result = null;
    let addend = point;
  
    while (scalar > 0n) {
      if (scalar & 1n) {
        result = pointAdd(result, addend, curve);
      }
  
      addend = pointAdd(addend, addend, curve);
      scalar >>= 1n;
    }
  
    return result;
}

// Compute the signature
async function sign(hash, privateKey) {
    let r, s;
    do {
        const k = multiply(toInt(Math.random().toString()), toInt(curve.n.toString()));
        const G = { x: curve.Gx, y: curve.Gy };
        const Q = pointMultiply(G, k, curve);
        const x = ((Q.x % curve.n) + curve.n) % curve.n;
        r = x === 0n ? sign(hash, privateKey) : x;

        const e = BigInt('0x' + hash);
        const d = BigInt('0x' + privateKey);
        s = ((modInverse(k, curve.n) * (e + d * r) % curve.n) + curve.n) % curve.n;
    } while (r === 0n || s === 0n);

    const signature = {
        r: r.toString(16).padStart(64, '0'),
        s: s.toString(16).padStart(64, '0')
    };
    return signature;
}

// Verify the signature
async function verify(hash, signature, publicKey) {
    const r = BigInt('0x' + signature.r);
    const s = BigInt('0x' + signature.s);
    const e = BigInt('0x' + hash);
    const Q = {
        x: BigInt('0x' + publicKey.slice(0, 64)),
        y: BigInt('0x' + publicKey.slice(64))
    };

    if (r <= 0n || r >= curve.n || s <= 0n || s >= curve.n) {
        return false;
    }

    const w = modInverse(s, curve.n);
    const u1 = (((e * w) % curve.n) + curve.n) % curve.n;
    const u2 = (((r * w) % curve.n) + curve.n) % curve.n;
    const G = { x: curve.Gx, y: curve.Gy };
    const P = pointAdd(pointMultiply(G, u1, curve), pointMultiply(Q, u2, curve), curve);

    if (P === null) {
        return false;
    }

    console.log(getPublicKey('d9576534d36bed4b1e8923b55dd0fb5a1a0a2cce9982c77b0778b6f0ac1b33a4'))
    console.log(r)
    console.log((((P.x % curve.n) + curve.n) % curve.n))

    return r === (((P.x % curve.n) + curve.n) % curve.n);
}

module.exports = {
    getRandomPrivateKey,
    getPublicKey,
    sign,
    verify
}
