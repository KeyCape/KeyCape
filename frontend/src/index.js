const { Elm } = require('./Main');
import * as bootstrap from 'bootstrap'
import './index.scss';

var app = Elm.Main.init({
	node: document.getElementById('myapp')
});

app.ports.sendRegister.subscribe(function(username) {
	register(username);
});

app.ports.sendLogin.subscribe(function(username) {
	login(username);
});

// Base64 to ArrayBuffer
function bufferDecode(value) {
	return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
	return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");;
}

async function register(username) {
	fetch('/register/begin/' + username)
		.then((response) => {
			if (!response.ok) {
				if (response.status == 404) {
					throw { "message": "Server not reachable. Try again later" };
				}
				throw { "message": response.status + ": " + response.statusText };
			}
			return response.json();
		})
		.then((credentialCreationOptions) => {
			console.log(credentialCreationOptions)
			credentialCreationOptions.challenge = bufferDecode(credentialCreationOptions.challenge);
			credentialCreationOptions.user.id = bufferDecode(credentialCreationOptions.user.id);
			// Prepare for excluded credentials
			if (credentialCreationOptions.excludeCredentials) {
				for (var i = 0; i < credentialCreationOptions.excludeCredentials.length; i++) {
					credentialCreationOptions.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.excludeCredentials[i].id);
				}
			}

			// Call the browsers API, in order to forward the request to security token, TPM, Passkey, ect.
			return navigator.credentials.create({
				publicKey: credentialCreationOptions
			});
		})
		.then((credential) => {
			console.log(credential)
			let attestationObject = credential.response.attestationObject;
			let clientDataJSON = credential.response.clientDataJSON;
			let rawId = credential.rawId;

			fetch('/register/finish/' + username, {
				method: 'POST',
				headers: new Headers({ 'Content-Type': 'application/json; charset=UTF-8' }),
				body: JSON.stringify({
					id: credential.id,
					rawId: bufferEncode(rawId),
					type: credential.type,
					response: {
						attestationObject: bufferEncode(attestationObject),
						clientDataJSON: bufferEncode(clientDataJSON),
					},
				})
			}).then((response) => {
				if (!response.ok) {
					if (response.status == 404) {
						throw { "message": "Server not reachable. Try again later" };
					}
					throw { "message": response.status + ": " + response.statusText };
				}
				// The user is registered
				app.ports.recvRegisterResult.send({ "msg": "Your account was successfully created", "error": false });
			}).catch((error) => {
				app.ports.recvRegisterResult.send({ "msg": error.message, "error": truex });
			})
		}).catch((error) => {
			// Send error to the elm app
			app.ports.recvRegisterResult.send({ "msg": error.message, "error": true });
		})
}

async function login(username) {
	fetch('/login/begin/' + username)
		.then((response) => {
			if (!response.ok) {
				if (response.status == 404) {
					throw { "message": "Server not reachable. Try again later" };
				}
				throw { "message": response.status + ": " + response.statusText };
			}
			return response.json();
		})
		.then((credentialRequestOptions) => {
			console.log(credentialRequestOptions)
			credentialRequestOptions.challenge = bufferDecode(credentialRequestOptions.challenge);
			credentialRequestOptions.allowCredentials.forEach(function(listItem) {
				listItem.id = bufferDecode(listItem.id)
			});

			// Call the browsers API, in order to forward the request to security token, TPM, Passkey, ect.
			return navigator.credentials.get({
				publicKey: credentialRequestOptions
			});
		})
		.then((assertion) => {
			console.log(assertion)
			let authData = assertion.response.authenticatorData;
			let clientDataJSON = assertion.response.clientDataJSON;
			let rawId = assertion.rawId;
			let sig = assertion.response.signature;
			let userHandle = assertion.response.userHandle;

			fetch('/login/finish/' + username, {
				method: 'POST',
				headers: new Headers({ 'Content-Type': 'application/json; charset=UTF-8' }),
				body: JSON.stringify({
					id: assertion.id,
					rawId: bufferEncode(rawId),
					type: assertion.type,
					response: {
						authenticatorData: bufferEncode(authData),
						clientDataJSON: bufferEncode(clientDataJSON),
						signature: bufferEncode(sig),
						userHandle: bufferEncode(userHandle),
					}
				})
			}).then((response) => {
				if (!response.ok) {
					if (response.status == 404) {
						throw { "message": "Server not reachable. Try again later" };
					}
					throw { "message": response.status + ": " + response.statusText };
				}
				// The user is registered
				app.ports.recvRegisterResult.send({ "msg": "Welcome back", "error": false });
			}).catch((error) => {
				app.ports.recvRegisterResult.send({ "msg": error.message, "error": true });
			})
		}).catch((error) => {
			// Send error to the elm app
			app.ports.recvRegisterResult.send({ "msg": error.message, "error": true });
		})
}
