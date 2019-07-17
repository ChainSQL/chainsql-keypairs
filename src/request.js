"use strict";

const request = require('request');

const verifyFailCode = 0x20100005;

function sendPost(url, requestData){
	return new Promise(function (resolve, reject) {
		request({
			url: url,
			method: "POST",
			json: true,
			headers: {
				"content-type": "application/json",
			},
			body: requestData
		}, function (error, response, body) {
			if (!error && response.statusCode == 200) {
				console.log(body);
				if (!body.retCode || body.retCode === verifyFailCode) {
					resolve(body);
				} else {
					reject(body);
				}
			} else {
				reject(error);
			}
		});
	})
}

module.exports = sendPost;