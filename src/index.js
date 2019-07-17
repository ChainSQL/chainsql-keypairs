'use strict' // eslint-disable-line strict

const assert = require('assert')
const brorand = require('brorand')
const hashjs = require('hash.js')
const elliptic = require('elliptic')
const Ed25519 = elliptic.eddsa('ed25519')
const Secp256k1 = elliptic.ec('secp256k1')
const addressCodec = require('chainsql-address-codec')
const derivePrivateKey = require('./secp256k1').derivePrivateKey
const accountPublicFromPublicGenerator = require('./secp256k1')
  .accountPublicFromPublicGenerator
const sendPost = require('./request')
const utils = require('./utils')
const hexToBytes = utils.hexToBytes
const bytesToHex = utils.bytesToHex

const sdServerUrl = "http://192.168.29.114:8000";
const ACCOUNT_PUBLIC = 35;

function generateSeed(options = {}) {
	assert(!options.entropy || options.entropy.length >= 16, 'entropy too short')
	const entropy = options.entropy ? options.entropy.slice(0, 16) : brorand(16)
//   const type = options.algorithm === 'ed25519' ? 'ed25519' : 'secp256k1'
	let type;
	switch (options.algorithm) {
		case "ed25519":
			type = "ed25519";
			break;
		case "secp256k1":
			type = "secp256k1";
			break;
		case "gmAlg":
			type = "gmAlg";
			break;
		default:
			type = "secp256k1";
	}
	if (type === "gmAlg") {
		return "gmAlg"
	} else {
		return addressCodec.encodeSeed(entropy, type);
	}
}

function hash(message) {
  return hashjs.sha512().update(message).digest().slice(0, 32)
}

const secp256k1 = {
  deriveKeypair: function(entropy, options) {
    const prefix = '00'
    const privateKey = prefix + derivePrivateKey(entropy, options)
      .toString(16, 64).toUpperCase()
    const publicKey = bytesToHex(Secp256k1.keyFromPrivate(
      privateKey.slice(2)).getPublic().encodeCompressed())
    return {privateKey, publicKey}
  },
  sign: function(message, privateKey) {
    return bytesToHex(Secp256k1.sign(hash(message),
      hexToBytes(privateKey), {canonical: true}).toDER())
  },
  verify: function(message, signature, publicKey) {
    return Secp256k1.verify(hash(message), signature, hexToBytes(publicKey))
  }
}

const ed25519 = {
  deriveKeypair: function(entropy) {
    const prefix = 'ED'
    const rawPrivateKey = hash(entropy)
    const privateKey = prefix + bytesToHex(rawPrivateKey)
    const publicKey = prefix + bytesToHex(
      Ed25519.keyFromSecret(rawPrivateKey).pubBytes())
    return {privateKey, publicKey}
  },
  sign: function(message, privateKey) {
    // caution: Ed25519.sign interprets all strings as hex, stripping
    // any non-hex characters without warning
    assert(Array.isArray(message), 'message must be array of octets')
    return bytesToHex(Ed25519.sign(
      message, hexToBytes(privateKey).slice(1)).toBytes())
  },
  verify: function(message, signature, publicKey) {
    return Ed25519.verify(message, hexToBytes(signature),
      hexToBytes(publicKey).slice(1))
  }
}

const gmAlg = {
	deriveKeypair: function(entropy) {
		const genKeyUrl = sdServerUrl + "/2/21";
		const getPubUrl = sdServerUrl + "/2/22";
		const postData = { containerIndex:0 };
		var privateKey = "", publicKey = "";
		try {
			const retGenKey = sendPost(genKeyUrl, postData);
			const retGetPub = sendPost(getPubUrl, postData);
			privateKey = "4700";
			// console.log(retGetPub.retCode);
			publicKey = retGetPub.publicKey;
		} catch (error) {
			throw new Error(error);
		}
		return {privateKey, publicKey}
	},
	sign: function(message, privateKey) {
		const sm3HashUrl = sdServerUrl + "/3";
		const sm2SignUrl = sdServerUrl + "/2/24";

		const msgHexStr = gmByte2HexStr(message);
		const postMessage = {
			data: msgHexStr,
			dataLen: message.length
		}
		try {
			const messageHash = sendPost(sm3HashUrl, postMessage);
			const postData4Sign = {
				data: messageHash.hashData,
				dataLen:32
			}
			const signRet = sendPost(sm2SignUrl, postData4Sign);
			return signRet.signedData;
		} catch (error) {
			throw new Error(error);
		}
	},
	verify: function(message, signature, publicKey) {
		const sm3HashUrl = sdServerUrl + "/3";
		const sm2VerifyUrl = sdServerUrl + "/2/25";
		const msgHexStr = gmByte2HexStr(message);
		const postMessage = {
			data: msgHexStr,
			dataLen: message.length
		}
		try {
			const messageHash = sendPost(sm3HashUrl, postMessage);
			const postData4Verify = {
				data: messageHash.hashData,
				dataLen:32,
				signedData: signature,
				signedDataLen: signature.length
			}
			const verifyRet = sendPost(sm2VerifyUrl, postData4Verify);
			return verifyRet.retCode === "0x00000000" ? true : false;
		} catch (error) {
			throw new Error(error);
		}
	}
}

function gmByte2HexStr(message) {
	let msgHexStr;
	let originalData = ArrayBuffer.isView(message) ? Buffer.from(message) : message;
	if (Array.isArray(originalData)) {
		msgHexStr = bytesToHex(originalData);
	} else if (Buffer.isBuffer(originalData)) {
		msgHexStr = originalData.toString('hex');
	} else {
		let errMsg = "Message data must be array or buffer";
		throw new Error(errMsg);
	}
	return msgHexStr;
}

function select(algorithm) {
	const methods = {"gmAlg": gmAlg, 'ecdsa-secp256k1': secp256k1, ed25519}
  return methods[algorithm]
}

function deriveKeypair(seed, options) {
	let decoded = {};
	if (seed === "gmAlg") {
		decoded.type = "gmAlg";
	} else {
		decoded = addressCodec.decodeSeed(seed);
	}

	let algorithm;
	switch (decoded.type) {
		case "ed25519":
			algorithm = "ed25519";
			break;
		case "secp256k1":
			algorithm = "ecdsa-secp256k1";
			break;
		case "gmAlg":
			algorithm = "gmAlg";
			break;
		default:
			algorithm = "ecdsa-secp256k1";
	}
	const method = select(algorithm)
	const keypair = method.deriveKeypair(decoded.bytes, options)
	const messageToVerify = hash('This test message should verify.')
	const signature = method.sign(messageToVerify, keypair.privateKey)
	if (method.verify(messageToVerify, signature, keypair.publicKey) !== true) {
		throw new Error('derived keypair did not generate verifiable signature')
	}
	return keypair
}

function getAlgorithmFromKey(key) {
  const bytes = hexToBytes(key)
  if(bytes.length === 65 || bytes.length === 2) {
	  if(bytes[0] === 0x47)
	  	return "gmAlg";
  } else {
    return (bytes.length === 33 && bytes[0] === 0xED) ?
      'ed25519' : 'ecdsa-secp256k1'
  }
}

function sign(messageHex, privateKey) {
  const algorithm = getAlgorithmFromKey(privateKey)
  return select(algorithm).sign(hexToBytes(messageHex), privateKey)
}

function signBytes(message, privateKey) {
  const algorithm = getAlgorithmFromKey(privateKey)
  return select(algorithm).sign(message, privateKey)
}

function verify(messageHex, signature, publicKey) {
  const algorithm = getAlgorithmFromKey(publicKey)
  return select(algorithm).verify(hexToBytes(messageHex), signature, publicKey)
}

function deriveAddressFromBytes(publicKeyBytes) {
  return addressCodec.encodeAccountID(
    utils.computePublicKeyHash(publicKeyBytes))
}

function deriveAddress(publicKey) {
  return deriveAddressFromBytes(hexToBytes(publicKey))
}

function deriveNodeAddress(publicKey) {
  const generatorBytes = addressCodec.decodeNodePublic(publicKey)
  const accountPublicBytes = accountPublicFromPublicGenerator(generatorBytes)
  return deriveAddressFromBytes(accountPublicBytes)
}

function gmAlgSm2Enc(keyIn, plainData) {
	let sm2EncUrl = sdServerUrl;
	let postMessage = {
		plainData: plainData,
		plainDataLen: plainData.length
	}
	if(keyIn === "gmAlg"){
		sm2EncUrl += "/2/26";
	} else {
		sm2EncUrl += "/2/30";
		let decoded = addressCodec.decode(keyIn, ACCOUNT_PUBLIC);
		let decodedPublic = decoded.slice(1, decoded.length-4);
		const decodedPublicHexStr = gmByte2HexStr(decodedPublic);
		postMessage.publicKey = decodedPublicHexStr;
		postMessage.publicKeyLen = decodedPublic.length;
	}
	
	try {
		const symEncRet = sendPost(sm2EncUrl, postMessage);
		return symEncRet.cipherData;
	} catch (error) {
		throw new Error(error);
	}
}

function gmAlgSm2Dec(priKey, cipherData) {
	const sm2DecUrl = sdServerUrl + "/2/27";
	const postMessage = {
		cipherData: cipherData,
		cipherDataLen: cipherData.length
	}
	try {
		const symEncRet = sendPost(sm2DecUrl, postMessage);
		return symEncRet.plainData;
	} catch (error) {
		throw new Error(error);
	}
}

function gmAlgSymEnc(symKey, plainData) {
	const sm4EncUrl = sdServerUrl + "/4/41";
	const postMessage = {
		key: symKey,
		keyLen: symKey.length,
		plainData: plainData,
		plainDataLen: plainData.length
	}
	try {
		const symEncRet = sendPost(sm4EncUrl, postMessage);
		return symEncRet.cipherData;
	} catch (error) {
		throw new Error(error);
	}
}

function gmAlgSymDec(symKey, cipherData) {
	const sm4DecUrl = sdServerUrl + "/4/42";
	const postMessage = {
		key: symKey,
		keyLen: symKey.length,
		cipherData: cipherData,
		cipherDataLen: cipherData.length
	}
	try {
		const symEncRet = sendPost(sm4DecUrl, postMessage);
		return symEncRet.plainData;
	} catch (error) {
		throw new Error(error);
	}
}

function gmAlgSm3(message) {
	const sm3HashUrl = sdServerUrl + "/3";
	const msgHexStr = gmByte2HexStr(message);
	const postMessage = {
		data: msgHexStr,
		dataLen: message.length
	}
	try {
		const messageHash = sendPost(sm3HashUrl, postMessage);
		return messageHash.hashData;
	} catch (error) {
		throw new Error(error);
	}
}

module.exports = {
  generateSeed,
  deriveKeypair,
  sign,
  signBytes,
  verify,
  deriveAddress,
  deriveNodeAddress,
  gmAlgSm2Enc,
  gmAlgSm2Dec,
  gmAlgSymEnc,
  gmAlgSymDec,
  gmAlgSm3
}
