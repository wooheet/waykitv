Math.seedrandom();
function cleanup(arr) {
  for (var i = 0; i < arr.length; i++) arr[i] = 0;
}
nacl.setPRNG(function(x, n) {
  var i,
    v = new Uint8Array(n).map(function() {
      return ~~(Math.random() * 256);
    });
  for (i = 0; i < n; i++) x[i] = v[i];
  cleanup(v);
});
nacl.util.encodeBase64 = function(arr) {
  var i,
    s = [],
    len = arr.length;
  for (i = 0; i < len; i++) s.push(String.fromCharCode(arr[i]));
  return base64.encode(s.join(""));
};

nacl.util.decodeBase64 = function(s) {
  var i,
    d = base64.decode(s),
    b = new Uint8Array(d.length);
  for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
  return b;
};

Meteor = {
  _id: null,
  userId: function() {
    return this._id;
  },
  user: function() {
    return {
      _id: this._id,
      emails: [
        {
          verified: true
        }
      ]
    };
  }
};
Collections = {
  users: [],
  principals: [],
  messages: []
};
// Encryption_onSignIn= function(password) {
//   return EncryptionUtils.onSignIn(password);
// };
/* util for debug */
objToArray = function(kk) {
  var s = [];
  for (var c in kk) s[c] = kk[c];
  return new Uint8Array(s);
};

/* convert object from Swift or mongo $binary type to Uint8Array */
var convertUint8ArrayObject = function(obj) {
  var t = Object.prototype.toString.call(obj);
  if (t === "[object Array]") {
    obj = obj.map(convertUint8ArrayObject);
  } else if (t === "[object Object]") {
    if (obj[0]) {
      obj = objToArray(obj);
    } else if (obj["$binary"]) {
      obj = nacl.util.decodeBase64(obj["$binary"]);
    } else {
      for (var key in obj) {
        obj[key] = convertUint8ArrayObject(obj[key]);
      }
    }
  }
  return obj;
};

/* Native Call : decryptMessage
   message를 decrypt하는 function
 */
var decryptMessage = function(doc) {
  var principal = EncryptionUtils.getPrincipal("messagesPrincipal", doc._id);
  var decryptedDocumentKey = EncryptionUtils.getDocumentKeyOfPrincipal(principal);
  doc["text"] = EncryptionUtils.symDecryptWithKey(doc["text"], principal.symNonce, decryptedDocumentKey);
  // set encrypted to false for better ui state handling
  if (doc["encrypted"]) {
    doc["encrypted"] = false;
  }
  return doc;
};
/* Native Call : encryptMessage
   encryptMessage Encrypt
   전제조건 : 챗방 안에 있는 모든 멤버에 대해 principals를 subscribe 하고 있을 것
   doc.id는 미리 서버로부터 받을 것

   for Test:
   sub=Meteor.subscribe('usersPrincipalForChat', Chats.findOne()._id)
   doc={
     "_id" : Random.id(),
     "chatId" : Chats.findOne()._id,
     "creator" : Session.getId(),
     "encrypted" : true,
     "messageType" : "text",
     "status" : "normal",
     "text" : 'just in time',
     "unreaders" : [],
     "createdAt" : "2016-11-01T08:56:23.150Z"
   };
   ww=encryptMessage(doc,Chats.findOne()._id)
 */
var encryptMessage = function(doc, chatId) {
  var documentKey = EncryptionUtils.generateRandomKey();
  var symNonce = EncryptionUtils.generate24ByteNonce();
  doc["text"] = EncryptionUtils.symEncryptWithKey(doc["text"], symNonce, documentKey);
  var keyPairForDocumentKey = nacl.box.keyPair();
  // userId가 첫번째로 오게끔.
  var members = [Session.getId()].concat(
    Chats.findOne({ _id: chatId })
      .members.map(function(o) {
        return o.userId;
      })
      .filter(function(o) {
        return o !== Session.getId();
      })
  );
  members &&
    members.length &&
    Principals.insert({
      dataType: "messagesPrincipal",
      dataId: doc._id,
      encryptedPrivateKeys: members
        .map(function(memberId) {
          return {
            id: memberId,
            userPrincipal: EncryptionUtils.getPrincipal("usersPrincipal", memberId)
          };
        })
        .filter(function(member) {
          return member.userPrincipal;
        })
        .map(function(member) {
          var asymNonce = EncryptionUtils.generate24ByteNonce();
          var userPrincipal = member.userPrincipal;
          return {
            userId: member.id,
            key: EncryptionUtils.asymEncryptWithKey(
              documentKey,
              asymNonce,
              userPrincipal.publicKey,
              keyPairForDocumentKey.secretKey
            ),
            asymNonce: asymNonce
          };
        }),
      publicKey: keyPairForDocumentKey.publicKey,
      privateKey: keyPairForDocumentKey.secretKey,
      symNonce: symNonce
    });
  return doc;
};

/* Native Call : store collections */
var setCollection = function(jsonString) {
  var obj = convertUint8ArrayObject(JSON.parse(jsonString));
  var status = {
    added: function(collection, id, fields) {
      Collections[collection] = Collections[collection] || [];
      Collections[collection].push(Object.assign(fields, { _id: id }));
    },
    changed: function(collection, id, fields) {
      var fw = _.findWhere(Collections[collection], { _id: id });
      Collections[collection] && fw && Object.assign(fw, fields);
    },
    removed: function(collection, id) {
      var fw = _.findWhere(Collections[collection], { _id: id });
      Collections[collection] && fw && Collections[collection].splice(Collections[collection].indexOf(fw), 1);
    }
  };
  status[obj.msg] && status[obj.msg](obj.collection, obj.id, obj.fields);
};

Session = {
  obj: {},
  setAuth: function(key, value) {
    this.obj[key] = value;
  },
  get: function(key) {
    return this.obj[key];
  }
};
/*
 Principals injection
 */
var document;
if (!document) {
  InsertPrincipals = function() {
    /* injected from native */
  };
  UpdatePrincipals = function() {
    /* injected from native */
  };
}
Chats = {
  findOne: function(obj) {
    return _.findWhere(Collections["chats"], obj);
  }
};

insertCollection = function(collection, obj) {
  if (!collection) {
    collection = [];
  }
  Object.assign(obj, { _id: Random.id() });
  collection.push(obj);
};

updateCollection = function(collection, condition, obj) {
  var target = _.where(collection, typeof condition === "object" && condition, { _id: condition });
  var pos = collection.indexOf(target);
  var mod = {
    $set: function(o) {
      return Object.assign(target, o);
    },
    $push: function(o) {
      for (var k in o) {
        var r = {};
        r[k] = (target[k] || []).concat(o[k]);
        target = Object.assign(target, r);
      }
      return target;
    },
    $pull: function(o) {
      for (var k in o) {
        var r = {};
        r[k] = _.filter(target[k], function(w) {
          return !_.isMatch(w, o[k]);
        });
        target = Object.assign(target, r);
      }
      return target;
    },
    "!!": function(o) {
      return o;
    }
  };
  for (var k in obj) {
    target = Object.assign(target, (mod[k] || mod["!!"])(obj[k]));
  }
  collection[pos] = target;
  return collection;
};

Principals = {
  findOne: function(obj) {
    return _.findWhere(Collections["principals"], obj);
  },
  clear: function() {
    Collections["principals"] = [];
  },
  added: function(obj) {
    Collections["principals"].push(obj);
  },
  changed: function(id, obj) {
    _.extend(_.findWhere(Collections["principals"], { id: id }), obj);
  },
  removed: function(id) {
    _.remove(Collections["principals"], { id: id });
  },
  insert: function(obj) {
    insertCollection(Collections["principals"], obj);
    InsertPrincipals(obj);
  },
  update: function(condition, obj) {
    updateCollection(Collections["principals"], condition, obj);
    UpdatePrincipals(condition, obj);
  }
};
