---
layout: default
---
<div class="container my-5">
	<div class="p-5 text-center bg-body-tertiary rounded-3">
		<h1 class="text-body-emphasis">{{ site.title }}</h1>
		<p class="col-lg-8 mx-auto fs-5 text-muted"> KeyCape is a zero password solution. It relies on signatures instead of passwords. You an authenticator of your choice: <b>YubiKey, Passkey, Smartphone, TPM</b></p>
		<div class="d-inline-flex gap-2 mb-5">
			<a class="d-inline-flex align-items-center btn btn-primary btn-lg px-4 rounded-pill" href="https://github.com/c3ai-lab/KeyCape"><i class="bi bi-github me-2"></i>Github</a>
			<a class="btn btn-outline-secondary btn-lg px-4 rounded-pill" href="https://jesper1995.gitbook.io/identity-provider-cpp/quick-start/prerequisites">Docs</a>
		</div>
	</div>
</div>
<div class="b-example-divider"></div>
<div class="container px-4 py-5">
	<h2 class="pb-2 border-bottom">Security aspects</h2>
	<div class="row g-4 py-5 row-cols-1 row-cols-lg-3">
	{% for entry in site.data.features %}
		<div class="col d-flex align-items-start">
			<div class="icon-square text-body-emphasis d-inline-flex align-items-center justify-content-center fs-4 flex-shrink-0 me-3">
				<i class="{{ entry.icon.name }}" style="color: {{ entry.icon.color }};"></i>
			</div>
			<div>
				<h3 class="fs-2 text-body-emphasis">{{ entry.title }}</h3>
				<p>{{ entry.content }}</p>
				{% if entry.link %}
				<a class="btn btn-primary" href="{{ entry.link }}">More</a>
				{% endif %}
			</div>
		</div>	
	{% endfor %}
	</div>
</div>
