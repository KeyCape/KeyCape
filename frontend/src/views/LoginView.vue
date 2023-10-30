<script lang="ts">
import { RouterLink, RouterView } from 'vue-router'
import { defineComponent } from 'vue'

export default defineComponent({
	data() {
		return {
			username: ""
		}
	},
	emits: ['on-success', 'on-error'],
	methods: {
		// Base64 to ArrayBuffer
		bufferDecode(value: any) {
			return Uint8Array.from(atob(value), c => c.charCodeAt(0));
		},

		// ArrayBuffer to URLBase64
		bufferEncode(value: any) {
			return btoa(String.fromCharCode.apply(null, Array.from<number>(new Uint8Array(value))))
				.replace(/\+/g, "-")
				.replace(/\//g, "_")
				.replace(/=/g, "");;
		},
		async login() {
			fetch('/login/begin/' + this.username)
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
					credentialRequestOptions.challenge = this.bufferDecode(credentialRequestOptions.challenge);
					credentialRequestOptions.allowCredentials.forEach((listItem: any) => {
						listItem.id = this.bufferDecode(listItem.id);
					});

					// Call the browsers API, in order to forward the request to security token, TPM, Passkey, ect.
					return navigator.credentials.get({
						publicKey: credentialRequestOptions
					});
				})
				.then((assertion) => {
					console.log(assertion)
					if (!isPubKeyCred(assertion)) {
						throw new TypeError("The returned Credential type has to be of type \"public-key\"");
					}
					if (!isAssResponse(assertion.response)) {
						throw new TypeError("The response type from the Authenticator should have been AuthenticatorAttestationResponse");
					}
					let authData = assertion.response.authenticatorData;
					let clientDataJSON = assertion.response.clientDataJSON;
					let rawId = assertion.rawId;
					let sig = assertion.response.signature;
					let userHandle = assertion.response.userHandle;

					fetch('/login/finish/' + this.username, {
						method: 'POST',
						headers: new Headers({ 'Content-Type': 'application/json; charset=UTF-8' }),
						body: JSON.stringify({
							id: assertion.id,
							rawId: this.bufferEncode(rawId),
							type: assertion.type,
							response: {
								authenticatorData: this.bufferEncode(authData),
								clientDataJSON: this.bufferEncode(clientDataJSON),
								signature: this.bufferEncode(sig),
								userHandle: this.bufferEncode(userHandle),
							}
						})
					}).then((response) => {
						if (!response.ok) {
							if (response.status == 404) {
								throw { "message": "Server not reachable. Try again later" };
							}
							throw { "message": response.status + ": " + response.statusText };
						}
						// The user is logged in
						this.$emit('on-success', 'Welcome back');
					}).catch((error) => {
						this.$emit('on-error', error.message);
					})
				}).catch((error) => {
					this.$emit('on-error', error.message);
				})
		}

	}
})

function isAssResponse(att: AuthenticatorResponse): att is AuthenticatorAssertionResponse {
	return (att as AuthenticatorAssertionResponse).authenticatorData != undefined;
}
function isPubKeyCred(cred: Credential | null): cred is PublicKeyCredential {
	return cred != null && cred.type === "public-key";
}
</script>

<template>
	<div class="row align-items-center justify-content-center" style="height:100vh">
		<div class="card text-center p-3 bg-opacity-10 bg-white border-0"
			style="width: 19em; box-shadow: rgba(255, 255, 255, 0.1) 0px 0px 2px;">
			<div class="card-title mb-2">
				<span class="bi bi-person-circle position-absolute top-0 start-50 translate-middle display-2 rounded-circle"
					style="background-color: rgb(12, 12, 28);line-height:0%;"></span>
			</div>
			<div class="card-body">
				<h1 class="pb-2">Sign in</h1>
				<p class="pb-2">Enter your username</p>
				<div class="mb-5">
					<input v-model="username" class="form-control" type="input">
					<div class="form-text">
						Not member yet?
						<RouterLink class="primary-link text-decoration-none" to="/register">Register
						</RouterLink>
					</div>
				</div>
				<div class="mb-2 d-grid">
					<button v-on:click="login" class="btn"
						style="background-color: rgb(42, 72, 99);">Login</button>
				</div>
			</div>
		</div>
	</div>
</template>
