const bcrypt = require('bcryptjs');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.question('Masukkan password yang ingin di-hash: ', async (pass) => {
  const hash = await bcrypt.hash(pass, 10);
  console.log('\nHash bcrypt untuk password tersebut:\n');
  console.log(hash);
  rl.close();
});