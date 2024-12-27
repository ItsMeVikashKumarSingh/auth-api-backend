const argon2 = require('argon2');

const argon2Config = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16, // 64 MiB
  timeCost: 3,         // 3 iterations
  parallelism: 1,      // Single thread
};

module.exports = argon2Config;
