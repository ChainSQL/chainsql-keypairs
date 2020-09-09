'use strict'; // eslint-disable-line strict

var assert = require('assert');
var hashjs = require('hash.js');
var BN = require('bn.js');

function bytesToHex(a) {
  return a.map(function (byteValue) {
    var hex = byteValue.toString(16).toUpperCase();
    return hex.length > 1 ? hex : '0' + hex;
  }).join('');
}


function stringToBytes(str){
  var arr = [];
  for (var i = 0, j = str.length; i < j; ++i) {
    arr.push(str.charCodeAt(i));
  }
 
  var tmpUint8Array = new Uint8Array(arr);
  return tmpUint8Array
}

function bytesToString(fileData){
  var dataString = "";
  for (var i = 0; i < fileData.length; i++) {
    dataString += String.fromCharCode(fileData[i]);
  }
  return dataString
}


function hexToBytes(a) {
  assert(a.length % 2 === 0);
  return new BN(a, 16).toArray(null, a.length / 2);
}

function computePublicKeyHash(publicKeyBytes) {
  var hash256 = hashjs.sha256().update(publicKeyBytes).digest();
  var hash160 = hashjs.ripemd160().update(hash256).digest();
  return hash160;
}

function seedFromPhrase(phrase) {
  return hashjs.sha512().update(phrase).digest().slice(0, 16);
}


// function hex2ASCII(hexx) {
//   var hex = hexx.toString();//force conversion
//   var str = '';
//   for (var i = 0; (i < hex.length && hex.substr(i, 2) !== '00'); i += 2)
//       str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
//   return str;
// }



/**
 * 解析utf8字符串到16进制
 */
function parseUtf8StringToHex(input) {
  input = unescape(encodeURIComponent(input))

  const length = input.length

  // 转换到字数组
  const words = []
  for (let i = 0; i < length; i++) {
    words[i >>> 2] |= (input.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
  }

  // 转换到16进制
  const hexChars = []
  for (let i = 0; i < length; i++) {
    const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    hexChars.push((bite >>> 4).toString(16))
    hexChars.push((bite & 0x0f).toString(16))
  }

  return hexChars.join('')
}

/**
 * 解析arrayBuffer到16进制字符串
 */
function parseArrayBufferToHex(input) {
  return Array.prototype.map.call(new Uint8Array(input), x => ('00' + x.toString(16)).slice(-2)).join('')
}




/**
 * 转成16进制串
 */
function arrayToHex(arr) {
  const words = []
  let j = 0
  for (let i = 0; i < arr.length * 2; i += 2) {
    words[i >>> 3] |= parseInt(arr[j], 10) << (24 - (i % 8) * 4)
    j++
  }

  // 转换到16进制
  const hexChars = []
  for (let i = 0; i < arr.length; i++) {
    const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    hexChars.push((bite >>> 4).toString(16))
    hexChars.push((bite & 0x0f).toString(16))
  }

  return hexChars.join('')
}

/**
 * 转成utf8串
 */
function arrayToUtf8(arr) {
  const words = []
  let j = 0
  for (let i = 0; i < arr.length * 2; i += 2) {
    words[i >>> 3] |= parseInt(arr[j], 10) << (24 - (i % 8) * 4)
    j++
  }

  try {
    const latin1Chars = []

    for (let i = 0; i < arr.length; i++) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      latin1Chars.push(String.fromCharCode(bite))
    }

    return decodeURIComponent(escape(latin1Chars.join('')))
  } catch (e) {
    throw new Error('Malformed UTF-8 data')
  }
}

/**
 * 转成ascii码数组
 */
function hexToArray(hexStr) {
  const words = []
  let hexStrLength = hexStr.length

  if (hexStrLength % 2 !== 0) {
    hexStr = leftPad(hexStr, hexStrLength + 1)
  }

  hexStrLength = hexStr.length

  for (let i = 0; i < hexStrLength; i += 2) {
    words.push(parseInt(hexStr.substr(i, 2), 16))
  }
  return words
}


/**
 * 解析utf8字符串到16进制
 */
function parseUtf8StringToHex(input) 
{

    input = unescape(encodeURIComponent(input))
    
    const length = input.length
    
    // 转换到字数组
    const words = []
    for (let i = 0; i < length; i++) {
      words[i >>> 2] |= (input.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
    }
    
    // 转换到16进制
    const hexChars = []
    for (let i = 0; i < length; i++) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      hexChars.push((bite >>> 4).toString(16))
      hexChars.push((bite & 0x0f).toString(16))
    }
    
    return hexChars.join('')
}


module.exports = {
  bytesToHex: bytesToHex,
  hexToBytes: hexToBytes,
  computePublicKeyHash: computePublicKeyHash,
  seedFromPhrase: seedFromPhrase,
  stringToBytes: stringToBytes,
  bytesToString: bytesToString,
  arrayToHex: arrayToHex,
  hexToArray: hexToArray,
  arrayToUtf8: arrayToUtf8,
  parseUtf8StringToHex: parseUtf8StringToHex,
};