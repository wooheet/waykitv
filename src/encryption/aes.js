import RNFetchBlob from "react-native-fetch-blob";
import File from "../util/file";
import Config from "../util/config";
var CryptoJS2 = require("crypto-js");

const TAG = "aes:";

function genKeys() {
  return {
    KEY: CryptoJS2.lib.WordArray.random(16).toString(),
    IV: CryptoJS2.lib.WordArray.random(16).toString(),
    SALT: CryptoJS2.lib.WordArray.random(16).toString()
  };
}
module.exports.genKeys = genKeys;

function genAesKey(keys) {
  return CryptoJS2.PBKDF2(keys.KEY, keys.SALT, {
    keySize: 256 / 32,
    iterations: 10
  });
}

function encryptPart(value, keys) {
  keys = keys ? keys : genKeys();
  let aesKey = genAesKey(keys);
  let aesIv = CryptoJS2.enc.Base64.parse(keys.IV);

  let encryptedValue = CryptoJS2.AES.encrypt(value, aesKey, {
    iv: aesIv,
    padding: CryptoJS2.pad.NoPadding,
    mode: CryptoJS2.mode.CTR
  });

  return encryptedValue.toString();
}
module.exports.encryptPart = encryptPart;

function decryptPart(value, keys) {
  let aesKey = genAesKey(keys);
  let aesIv = CryptoJS2.enc.Base64.parse(keys.IV);
  let decryptedValue = null;

  if (value) {
    try {
      decryptedValue = CryptoJS2.AES.decrypt(value, aesKey, {
        iv: aesIv,
        padding: CryptoJS2.pad.NoPadding,
        mode: CryptoJS2.mode.CTR
      });

      decryptedValue = decryptedValue.toString(CryptoJS2.enc.Utf8);
    } catch (e) {}
  } else {
    value = "";
  }

  if (!decryptedValue) {
    decryptedValue = value;
  }

  return decryptedValue.toString();
}
module.exports.decryptPart = decryptPart;

const encInput = "base64";
const encOutput = "base64";
//const encOutput = 'utf8';
const fileOutput = "utf8";
//const fileOutput = 'base64';

async function encryptFile(srcInfo, dstInfo, keys) {
  let fileContents = await RNFetchBlob.fs.readFile(File.safePath(srcInfo), encInput);
  if (!fileContents) {
    throw "failed to read path:" + File.safePath(srcInfo);
  }

  let sliceList = fileContents.match(new RegExp(".{1," + "5242880" + "}", "g"));

  sliceList = sliceList.map(plainChunk => {
    return encryptPart(plainChunk, keys);
  });

  await RNFetchBlob.fs.writeFile(File.safePath(dstInfo), sliceList.join("!!NOD!!"), fileOutput);
}
module.exports.encryptFile = encryptFile;

async function decryptFile(srcInfo, dstInfo, keys) {
  const fileContents = await RNFetchBlob.fs.readFile(File.safePath(srcInfo), fileOutput);
  if (!fileContents) {
    throw "failed to read path:" + File.safePath(srcInfo);
  }

  let originDecrypted = "";

  // let chunkedList = _.compact(fileContents.split('!!NOD!!'));
  let chunkedList = fileContents.split("!!NOD!!");

  chunkedList = chunkedList.map(encryptedChunk => {
    return decryptPart(encryptedChunk, keys);
  });

  originDecrypted = chunkedList.join("");

  let indexBase64 = originDecrypted.indexOf(";base64,");
  if (indexBase64 != -1) {
    indexBase64 = indexBase64 + ";base64,".length;
  } else {
    indexBase64 = 0;
  }

  originDecrypted = originDecrypted.substring(indexBase64);

  await RNFetchBlob.fs.writeFile(File.safePath(dstInfo), originDecrypted, encInput);
}
module.exports.decryptFile = decryptFile;

// ----------------------------------------------------------------------------------------------------

async function encryptFileThumb(srcInfo, dstInfo, keys) {
  let fileContents = await RNFetchBlob.fs.readFile(File.safePath(srcInfo), encInput);
  if (!fileContents) {
    throw "failed to read path:" + File.safePath(srcInfo);
  }

  let sliceList = fileContents.match(new RegExp(".{1," + "5242880" + "}", "g"));

  sliceList = sliceList.map(plainChunk => {
    return plainChunk;
  });

  await RNFetchBlob.fs.writeFile(File.safePath(dstInfo), sliceList.join("!!NOD!!"), fileOutput);
}
module.exports.encryptFileThumb = encryptFileThumb;

async function decryptFileThumb(srcInfo, dstInfo, keys) {
  const fileContents = await RNFetchBlob.fs.readFile(File.safePath(srcInfo), fileOutput);
  if (!fileContents) {
    throw "failed to read path:" + File.safePath(srcInfo);
  }

  let originDecrypted;

  let chunkedList = fileContents.split("!!NOD!!");

  chunkedList = chunkedList.map(encryptedChunk => {
    return encryptedChunk;
  });

  originDecrypted = chunkedList.join("");

  let indexBase64 = originDecrypted.indexOf(";base64,");
  if (indexBase64 != -1) {
    indexBase64 = indexBase64 + ";base64,".length;
  } else {
    indexBase64 = 0;
  }

  originDecrypted = originDecrypted.substring(indexBase64);

  await RNFetchBlob.fs.writeFile(File.safePath(dstInfo), originDecrypted, encInput);
}
module.exports.decryptFileThumb = decryptFileThumb;
