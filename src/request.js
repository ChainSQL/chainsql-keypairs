"use strict";

const request = require('sync-request');

const verifyFailCode = "0x‭20100005‬";
const execSuccess = "0x00000000"

function sendPost(url, requestData){
	const response = request('POST', url, {
		json: requestData,
		timeout:3000
	});
	// console.log(response);
	const bodyRetJson = JSON.parse(response.getBody('utf8'));
	if(bodyRetJson.retCode === execSuccess || bodyRetJson.retCode === verifyFailCode){
		return bodyRetJson;
	} else {
		throw new Error(JSON.stringify(bodyRetJson));
	}
}

module.exports = sendPost;