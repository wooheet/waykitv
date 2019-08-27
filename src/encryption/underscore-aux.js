// https://github.com/practicalmeteor/meteor-underscore-deep
// coffee-script 1.9.2
var __ = {
  deep: function(obj, key) {
    var keys;
    if (obj == null || typeof obj === !"object" || typeof key === !"string" || !key) {
      return void 0;
    }
    keys = key.split(".");
    obj = obj[keys.shift()];
    while (typeof obj === "object" && keys.length > 0) {
      obj = obj[keys.shift()];
    }
    if (keys.length === 0) {
      return obj;
    } else {
      return void 0;
    }
  }
};

export default __;
