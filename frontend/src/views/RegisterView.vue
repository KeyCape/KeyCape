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
		async register() {
			fetch('/register/begin/' + this.username)
				.then((response) => {
					if (!response.ok) {
						if (response.status == 404) {
							throw new Error("Server not reachable. Try again later");
						}
						throw new Error(response.status + ": " + response.statusText );
					}
					return response.json();
				})
				.then((credentialCreationOptions) => {
					console.log(credentialCreationOptions)
					credentialCreationOptions.challenge = this.bufferDecode(credentialCreationOptions.challenge);
					credentialCreationOptions.user.id = this.bufferDecode(credentialCreationOptions.user.id);
					// Prepare for excluded credentials
					if (credentialCreationOptions.excludeCredentials) {
						for (var i = 0; i < credentialCreationOptions.excludeCredentials.length; i++) {
							credentialCreationOptions.excludeCredentials[i].id = this.bufferDecode(credentialCreationOptions.excludeCredentials[i].id);
						}
					}

					// Call the browsers API, in order to forward the request to security token, TPM, Passkey, ect.
					return navigator.credentials.create({
						publicKey: credentialCreationOptions
					});
				})
				.then((credential) => {
					console.log(credential)
					// By the time of writing, WebAuthn only defined the type public-key
					if (!isPubKeyCred(credential)) {
						throw new TypeError("The returned Credential type has to be of type \"public-key\"");
					}

					if (!isAttResponse(credential.response)) {
						throw new TypeError("The response type from the Authenticator should have been AuthenticatorAttestationResponse");
					}

					let attestationObject = credential.response.attestationObject;
					let clientDataJSON = credential.response.clientDataJSON;
					let rawId = credential.rawId;

					fetch('/register/finish/' + this.username, {
						method: 'POST',
						headers: new Headers({ 'Content-Type': 'application/json; charset=UTF-8' }),
						body: JSON.stringify({
							id: credential.id,
							rawId: this.bufferEncode(rawId),
							type: credential.type,
							response: {
								attestationObject: this.bufferEncode(attestationObject),
								clientDataJSON: this.bufferEncode(clientDataJSON),
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
						this.$emit('on-success', 'Your account has been created successfully');
					}).catch((error) => {
						this.$emit('on-error', error.message);
					})
				}).catch((error) => {
					this.$emit('on-error', error.message);
				})
		}
	}
})

function isAttResponse(att: AuthenticatorResponse): att is AuthenticatorAttestationResponse {
	return (att as AuthenticatorAttestationResponse).attestationObject != undefined;
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
				<h1 class="pb-2">Sign up</h1>
				<p class="pb-2">Enter your username</p>
				<div class="mb-5">
					<input v-model="username" class="form-control" type="input">
					<div class="form-text">
						Already a member?
						<RouterLink class="primary-link text-decoration-none" to="/login">Login</RouterLink>
					</div>
				</div>
				<div class="mb-2 d-grid">
					<button v-on:click="register" class="btn" style="background-color: rgb(42, 72, 99);">Register</button>
				</div>
			</div>
		</div>
	</div>
</template>
