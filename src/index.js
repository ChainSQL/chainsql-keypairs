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

const sdServerUrl = "http://192.168.29.120:8000"

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

const gmSM2 = {
	deriveKeypair: async function(entropy) {
		const genKeyUrl = sdServerUrl + "/2/21";
		const getPubUrl = sdServerUrl + "/2/22";
		const postData = { containerIndex:0 };
		var privateKey = "", publicKey = "";
		try {
			const retGenKey = await sendPost(genKeyUrl, postData);
			const retGetPub = await sendPost(getPubUrl, postData);
			privateKey = "4700";
			// console.log(retGetPub.retCode);
			publicKey = retGetPub.publicKey;
		} catch (error) {
			throw new Error(error);
		}
		return {privateKey, publicKey}
	},
	sign: async function(message, privateKey) {
		const sm3HashUrl = sdServerUrl + "/3";
		const sm2SignUrl = sdServerUrl + "/2/24";
		const postMessage = {
			data: bytesToHex(message),
			dataLen: message.length
		}
		try {
			const messageHash = await sendPost(sm3HashUrl, postMessage);
			const postData4Sign = {
				data: messageHash.hashData,
				dataLen:32
			}
			const signRet = await sendPost(sm2SignUrl, postData4Sign);
			return signRet.signedData;
		} catch (error) {
			throw new Error(error);
		}
	},
	verify: async function(message, signature, publicKey) {
		const sm3HashUrl = sdServerUrl + "/3";
		const sm2VerifyUrl = sdServerUrl + "/2/25";
		const postMessage = {
			data: bytesToHex(message),
			dataLen: message.length
		}
		try {
			const messageHash = await sendPost(sm3HashUrl, postMessage);
			const postData4Verify = {
				data: messageHash.hashData,
				dataLen:32,
				signedData: signature,
				signedDataLen: signature.length
			}
			const verifyRet = await sendPost(sm2VerifyUrl, postData4Verify);
			return verifyRet.retCode ? false : true;
		} catch (error) {
			throw new Error(error);
		}
	}
}

function select(algorithm) {
  const methods = {'ecdsa-secp256k1': secp256k1, ed25519, "gmSM2": gmSM2}
  return methods[algorithm]
}

function deriveKeypair(seed, options) {
//   const decoded = addressCodec.decodeSeed(seed)
//   const algorithm = decoded.type === 'ed25519' ? 'ed25519' : 'ecdsa-secp256k1'
	let decoded = {};
	if (seed === "gmAlg") {
		decoded.type = "gmAlg";
	} else {
		decoded = addressCodec.decodeSeed(seed);
	}
	//   var algorithm = decoded.type === 'ed25519' ? 'ed25519' : 'ecdsa-secp256k1';
	let algorithm;
	switch (decoded.type) {
		case "ed25519":
			algorithm = "ed25519";
			break;
		case "secp256k1":
			algorithm = "secp256k1";
			break;
		case "gmAlg":
			algorithm = "gmAlg";
			break;
		default:
			algorithm = "secp256k1";
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
  return (bytes.length === 33 && bytes[0] === 0xED) ?
    'ed25519' : 'ecdsa-secp256k1'
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

module.exports = {
  generateSeed,
  deriveKeypair,
  sign,
  signBytes,
  verify,
  deriveAddress,
  deriveNodeAddress
}
