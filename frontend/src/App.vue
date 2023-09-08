<script lang="ts">
import { RouterLink, RouterView } from 'vue-router'
import { defineComponent } from 'vue'
export default defineComponent({
	data() {
		return {
			username: "",
			error: "",
			success: "",
		}
	},
	methods: {
		onError(msg: string) {
			this.error = msg;
		},
		onSuccess(msg: string) {
			this.success = msg;
		}
	}
})
</script>

<template>
	<nav class="navbar navbar-expand-lg bg-body-tertiary sticky-top">
		<div class="container container-fluid">
			<a href="/" class="navbar-brand">KeyCape</a>
			<div class="collapse navbar-collapse">
				<div class="navbar-nav">
					<RouterLink class="nav-link" to="/">Home</RouterLink>
				</div>
			</div>
			<div class="navbar-nav">
				<RouterLink class="btn btn-outline-secondary me-2" to="/register">Register</RouterLink>
				<RouterLink class="btn btn-outline-success" to="/login">Login</RouterLink>
			</div>
		</div>
	</nav>
	<div class="container">
		<template v-if="error.length > 0">
			<div class="alert alert-danger" role="alert">{{ error }}</div>
		</template>
		<template v-if="success.length > 0">
			<div class="alert alert-success" role="alert">{{ success }}</div>
		</template>
		<RouterView v-on:on-error="onError" v-on:on-success="onSuccess" />
	</div>
</template>

<style scoped></style>
