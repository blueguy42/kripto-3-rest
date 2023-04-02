// SHA-3 constants
const RC = [
    "0x0000000000000001", "0x0000000000008082", "0x800000000000808a",
    "0x8000000080008000", "0x000000000000808b", "0x0000000080000001",
    "0x8000000080008081", "0x8000000000008009", "0x000000000000008a",
    "0x0000000000000088", "0x0000000080008009", "0x000000008000000a",
    "0x000000008000808b", "0x800000000000008b", "0x8000000000008089",
    "0x8000000000008003", "0x8000000000008002", "0x8000000000000080",
    "0x000000000000800a", "0x800000008000000a", "0x8000000080008081",
    "0x8000000000008080", "0x0000000080000001", "0x8000000080008008"
];

// Message padding
const padMessage = (message) => {
    let paddedMessage = message;
    const blockByteSize = 200 - 2 * 32;
    const messageByteLen = message.length;
    const numOfBlocks = (blockByteSize - 1 - 2) / 8;
    const numOfPads = numOfBlocks * 8 - (messageByteLen % numOfBlocks);

    if (numOfPads == 1) {
        paddedMessage += String.fromCharCode(0x86);
    } else {
        paddedMessage += String.fromCharCode(0x06);
        for (let i = 0; i < numOfPads - 2; i += 2) {
        paddedMessage += String.fromCharCode(0x00) + String.fromCharCode(0x00);
        }
        paddedMessage += String.fromCharCode(0x80);
    }

    return paddedMessage;
};

// Convert message to binary string
const toBinaryString = (message) => {
    let binaryString = "";
    for (let i = 0; i < message.length; i++) {
        const charCode = message.charCodeAt(i);
        binaryString += ("00000000" + charCode.toString(2)).slice(-8);
    }
    return binaryString;
};

// Convert binary string to hex string
const toHexString = (binaryString) => {
    let hexString = "";
    for (let i = 0; i < binaryString.length; i += 8) {
        const byte = binaryString.substr(i, 8);
        hexString += ("0" + parseInt(byte, 2).toString(16)).slice(-2);
    }
    return hexString;
};

// Rotations
const rotate = (x, n) => {
    return ((x << n) | (x >>> (64 - n))) >>> 0;
};

// Keccak-f permutation
const keccakF = (state) => {
    for (let round = 0; round < 24; round++) {
        // Theta step
        const C = Array(5).fill().map((_, i) => state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3] ^ state[i][4]);
        const D = Array(5).fill().map((_, i) => C[(i + 4) % 5] ^ rotate(C[(i + 1) % 5], 1));
        state = state.map((lane, i) => lane.map((x, j) => x ^ D[j]));
        
        // Rho and pi steps
        let x = state[1][0];
        let y = state[1][1];
        for (let t = 0; t < 24; t++) {
        const tx = x;
        x = ((y % 5) + 5) % 5;
        y = (((2 * tx + 3 * y) % 5) + 5) % 5;
        const z = state[x][y];
        state[x][y] = rotate(state[(x + 1) % 5][y], RC[t]);
        RC[t] = ((RC[t] << ((t + 1) % 64)) | (RC[t] >>> (64 - (t + 1)))) >>> 0;
        state[(x + 1) % 5][y] = z;
        }
        
        // Chi step
        state = state.map((lane, i) => {
        const [a, b, c, d, e] = lane;
        return [
            a ^ ((~b) & c),
            b ^ ((~c) & d),
            c ^ ((~d) & e),
            d ^ ((~e) & a),
            e ^ ((~a) & b)
        ];
        });
        
        // Iota step
        state[0][0] = state[0][0] ^ RC[round];
    }
    return state;
};

async function hash(message) {
    // Convert message to binary string
    const binaryMessage = toBinaryString(padMessage(message));
    
    // Initialize state
    let state = Array(5).fill().map(() => Array(5).fill(0));
    for (let i = 0; i < binaryMessage.length; i += 8) {
      const byte = binaryMessage.substr(i, 8);
      const laneIndex = Math.floor(i / 8) % 25;
      const laneX = laneIndex % 5;
      const laneY = Math.floor(laneIndex / 5);
      state[laneY][laneX] ^= parseInt(byte, 2);
    }
    state = keccakF(state);
    
    // Output transformation
    const outputLen = 256;
    let output = "";
    while (output.length < outputLen) {
      let block = "";
      for (let i = 0; i < state.length; i++) {
        for (let j = 0; j < state[i].length; j++) {
          const lane = state[i][j];
          block += ("00000000" + lane.toString(2)).slice(-8);
        }
      }
      output += toHexString(block.substr(0, Math.min(outputLen - output.length, block.length)));
      state = keccakF(state);
    }
    return output;
};
  

module.exports = {
    hash
}