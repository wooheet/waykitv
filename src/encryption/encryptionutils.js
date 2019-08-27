import _ from 'underscore';
import '../../shim';
const crypto = require('crypto');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');

EncryptionUtils = {
  deep: function(obj, key) {
    var keys;
    if (obj == null || typeof obj === !'object' || typeof key === !'string' || !key) {
      return void 0;
    }
    keys = key.split('.');
    obj = obj[keys.shift()];
    while (typeof obj === 'object' && keys.length > 0) {
      obj = obj[keys.shift()];
    }
    if (keys.length === 0) {
      return obj;
    } else {
      return void 0;
    }
  },
  setDeep: function(obj, path, value) {
    var i;
    path = path.split('.');
    for (i = 0; i < path.length - 1; i++) {
      var emptyObj = {};
      emptyObj[path[i]] = null;
      obj = obj[path[i]] || emptyObj;
    }

    if (!value) {
      delete obj[path[i]];
    } else {
      obj[path[i]] = value;
    }
  },
  userId: function() {
    return Meteor.userId();
  },
  setPrivateKey: function(privateKey) {
    signedInSession.setAuth('privateKey', {
      privateKey: privateKey
    });
  },
  decryptDoc: function(doc, fields, name, encryptedFieldKey) {
    var self = this;

    // var principal = self.getPrincipal(name, doc._id);
    var principal = doc.principal;

    if (!principal) {
      return doc;
    }

    var decryptedDocumentKey = self.getDocumentKeyOfPrincipal(principal);

    if (!decryptedDocumentKey) {
      return doc;
    }

    _.each(fields, function(field) {
      if (self.deep(doc, field)) {
        self.setDeep(
          doc,
          field,
          self.symDecryptWithKey(self.deep(doc, field), principal.symNonce, decryptedDocumentKey)
        );
      }
    });

    doc[encryptedFieldKey] = false;
    return doc;
  },
  asymEncryptWithKey: function(message, nonce, publicKey, secretKey) {
    return nacl.box(message, nonce, publicKey, secretKey);
  },
  symEncryptWithKey: function(message, nonce, key) {
    var returnAsString = _.isString(message);
    if (returnAsString) {
      message = nacl.util.decodeUTF8(message);
    }
    var encryptedMessage = nacl.secretbox(message, nonce, key);
    if (returnAsString) {
      return nacl.util.encodeBase64(encryptedMessage);
    }
    return encryptedMessage;
  },
  asymDecryptWithKey: function(message, nonce, publicKey, secretKey) {
    return nacl.box.open(message, nonce, publicKey, secretKey);
  },
  symDecryptWithKey: function(cipher, nonce, key) {
    var returnAsString = _.isString(cipher);
    if (returnAsString) {
      cipher = nacl.util.decodeBase64(cipher);
    }
    // console.log('ciphter', cipher);
    // console.log('nonce', nonce);
    // console.log('key', key);
    var decryptedMessage = nacl.secretbox.open(cipher, nonce, key);

    if (returnAsString) {
      return nacl.util.encodeUTF8(decryptedMessage);
    }
    return decryptedMessage;
  },
  generateRandomKey: function(randomBytes) {
    // if (window.secureShared && window.secureShared.generatePassphrase) {
    var self = this,
      byteArray = nacl.util.decodeUTF8(crypto.randomBytes(16).toString());

    if (byteArray.length < 32) {
      if (!randomBytes) {
        randomBytes = nacl.randomBytes(32 - byteArray.length);
      }

      byteArray = self.appendBuffer(byteArray, randomBytes);
    } else {
      // byteArray = byteArray.slice(0, 31);
      let array32 = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        array32[i] = byteArray[i];
      }
      byteArray = array32;
    }

    return byteArray;
    // }
  },
  getDocumentKeyOfPrincipal: function(principal, myUserId, privateKey) {
    if (!principal) {
      return;
    }

    let self = this,
      searchObj = {
        userId: myUserId
      },
      myPrivateKey = privateKey,
      encryptedKeys = _.where(principal.encryptedPrivateKeys, searchObj);

    if (!encryptedKeys.length) {
      return;
    }

    let key = new Uint8Array(encryptedKeys[0].key);
    let asymNonce = new Uint8Array(encryptedKeys[0].asymNonce);
    let publicKey = new Uint8Array(principal.publicKey);

    return self.asymDecryptWithKey(key, asymNonce, publicKey, myPrivateKey);
  },
  getPrincipal: function(type, dataId) {
    return Meteor.collection('principals').findOne({
      dataType: type,
      dataId: dataId
    });
  },
  shareDocWithUser: function(docId, docType, userId, externalDoc) {
    var self = this,
      asymNonce = self.generate24ByteNonce();

    var userPrincipal = self.getPrincipal('usersPrincipal', userId);
    if (!userPrincipal) {
      return false;
    }

    var documentPrincipal = externalDoc === undefined ? self.getPrincipal(docType, docId) : externalDoc;
    if (!documentPrincipal) {
      return false;
    }

    var userPublicKey = userPrincipal.publicKey;
    var secretKeyForDocumentKey = documentPrincipal.privateKey;
    var documentKey = self.getDocumentKeyOfPrincipal(documentPrincipal);
    var encryptedDocumentKey = self.asymEncryptWithKey(documentKey, asymNonce, userPublicKey, secretKeyForDocumentKey);

    var val = {
      $push: {
        encryptedPrivateKeys: {
          userId: userId,
          key: encryptedDocumentKey,
          asymNonce: asymNonce
        }
      }
    };

    if (externalDoc === undefined) {
    } else {
      externalDoc.encryptedPrivateKeys.push(val.$push.encryptedPrivateKeys);
    }

    return true;
  },
  generate24ByteNonce: function() {
    return nacl.randomBytes(24);
  },
  generate32ByteKeyFromPassword: function(password, randomBytes) {
    var self = this,
      byteArray = nacl.util.decodeUTF8(password);
    if (byteArray.length < 32) {
      if (!randomBytes) {
        randomBytes = nacl.randomBytes(32 - byteArray.length);
      }

      byteArray = self.appendBuffer(byteArray, randomBytes);
    } else {
      // byteArray = byteArray.slice(0, 31);
      let array32 = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        array32[i] = byteArray[i];
      }
      byteArray = array32;
    }

    return {
      byteArray: byteArray,
      randomBytes: randomBytes
    };
  },
  appendBuffer: function(buffer1, buffer2) {
    var tmp = new Uint8Array(buffer1.length + buffer2.length);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.length);

    return tmp;
  },
  getPrivateKey: function(message, chatPrincipal) {
    return new Uint8Array(_.values(signedInSession.get('privateKey').privateKey));
  },
  decryptMessage: function(message, chatPrincipal, userId, privateKey) {
    // console.log('message', message);
    if (!chatPrincipal) {
      return 'Encrypted message';
    }
    const chatDocumentKey = this.getDocumentKeyOfPrincipal(chatPrincipal, userId, privateKey.chatPrivateKey);
    const symNonce = new Uint8Array(chatPrincipal.symNonce);
    const result = this.symDecryptWithKey(message, symNonce, chatDocumentKey);
    return result;
  }
};

module.exports = EncryptionUtils;
