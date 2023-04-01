async function createKey(email) {
    // this is a placeholder for now
    return {
        public_key: Date.now(),
        private_key: Date.now()+1
    };
}

module.exports = {
    createKey
}