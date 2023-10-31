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
			<a href="/" class="navbar-brand"><img src="/keycape_transparent_bg.png" width="100" height="100" style="position: absolute; left: calc(50% - 50px); top: 2px;"></a>
			<div class="collapse navbar-collapse">
				<div class="navbar-nav">
					<RouterLink class="nav-link" to="/"><i class="bi bi-house"></i> Home</RouterLink>
				</div>
			</div>
			<div class="navbar-nav">
				<RouterLink class="nav-link" to="/login"><i class="bi bi-box-arrow-in-right"></i> Sign in</RouterLink>
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
