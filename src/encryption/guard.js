import React from "react";
import { AsyncStorage } from "react-native";

var Meteor = {};
var Match = {
  Optional: function() {}
};

window = this;

var signedInSession = {
  keys: {},
  get: function(key) {
    return this.keys[key];
  },
  setAuth: function(key, value) {
    this.keys[key] = value;
    return;
  }
};

/*
var signedInSession = {
  
  get: async function(key) {
    try {
      const value = await AsyncStorage.getItem(key);
      if (value !== null){
        // We have data!!
        return JSON.parse(value);
      }
    } catch (error) {
      return null;
    }
  },
  setAuth: async function(key,value) {
    try {
      value = value.privateKey;

      await AsyncStorage.setItem(key, value);
      return true;
    } catch (error) {
      // Error saving data
      return false;
    }
    return;
  }
};
*/
/*
      //test
      var origin = value.privateKey;
      var stringify = EJSON.stringify(value);
      var json = EJSON.parse(stringify);
      var recover = json.privateKey;

*/

var getPrivateKey = function() {
  var privateKeyObj = signedInSession.get("privateKey");
  if (privateKeyObj && privateKeyObj.privateKey) {
    return new Uint8Array(_.values(privateKeyObj.privateKey));
  }
  return null;
};
var setPrivateKey = function(privateKey) {
  return EncryptionUtils.setPrivateKey(privateKey);
};
var check = function() {};
var self = this;
var Buffer = Uint8Array;

//fix for react-native
global.signedInSession = signedInSession;
global.Meteor = Meteor;
global.Match = Match;
Meteor.isClient = true;
