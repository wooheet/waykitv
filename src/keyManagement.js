import EncryptionUtils from './encryption/encryptionutils';
const nacl = require('tweetnacl');

let privateKey = new Uint8Array(nacl.util.decodeUTF8(pk));
const symNonce = EncryptionUtils.generate24ByteNonce();

const encryption = () => {
    scrypt(
        inputPassword,
        'saltysalt',
        {
        N: process.env.SCRYPT_N,
        r: process.env.SCRYPT_R,
        p: process.env.SCRYPT_P,
        dkLen: process.env.SCRYPT_DKLEN,
        encoding: process.env.SCRYPT_ENCODING,
        interruptStep: process.env.SCRYPT_INTERRUPTSTEP
        },
        passDerivedKey => {
            const password = EncryptionUtils.generate32ByteKeyFromPassword(passDerivedKey);
            let passPrivateKey = EncryptionUtils.symEncryptWithKey(privateKey, symNonce, password.byteArray);

        });
    //db
    const principalData = {
        passPrivateKey,
        symNonce
    };
}



const decryption = () => {
    scrypt(
        password,
        'saltysalt',
        {
          N: process.env.SCRYPT_N,
          r: process.env.SCRYPT_R,
          p: process.env.SCRYPT_P,
          dkLen: process.env.SCRYPT_DKLEN,
          encoding: process.env.SCRYPT_ENCODING,
          interruptStep: process.env.SCRYPT_INTERRUPTSTEP
        },
        passDerivedKey => {
          let encryptPassPrivateKey = new Uint8Array(self.props.myInfo.principal.passPrivateKey);
          let nonce = new Uint8Array(self.props.myInfo.principal.symNonce);
          let passwordKdf = EncryptionUtils.generate32ByteKeyFromPassword(passDerivedKey);
          let decryptPrivateKey = EncryptionUtils.symDecryptWithKey(encryptPassPrivateKey, nonce, passwordKdf.byteArray);
          const privateKey = self.uint8arrayToStringMethod(decryptPrivateKey);
          
          if (!privateKey) {
            
          } 
        }
      );   
}
