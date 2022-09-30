const crypto = require('crypto');
const secretkey = crypto.randomBytes(20).toString('hex');
//console.log(secretkey);
module.exports.secretkey = secretkey;