---
layout: default
---
<div class="container-fluid" id="banner">
<div class="row align-items-center justify-content-center" style="height:90vh">
	<div class="col-lg-6 text-center">
		<img src="assets/img/favicon.png" class="d-inline-block align-text-top" alt="Logo" width="256">
		<h1 class="text-body-emphasis display-2">{{ site.title }}</h1>
		<p class="col-lg-8 mx-auto fs-5 text-muted fs-4"> KeyCape is a zero password solution. It relies on signatures instead of passwords. You an authenticator of your choice: <b>YubiKey, Passkey, Smartphone, TPM</b></p>
		<div class="d-inline-flex gap-2 mb-5">
			<a class="d-inline-flex align-items-center btn btn-primary btn-lg px-4 rounded-pill" href="https://github.com/KeyCape/KeyCape"><i class="bi bi-github me-2"></i>Github</a>
			<a class="btn btn-outline-secondary btn-lg px-4 rounded-pill" href="https://jesper1995.gitbook.io/identity-provider-cpp/quick-start/prerequisites">Docs</a>
		</div>
	</div>
</div>
<div class="row align-items-start justify-content-center" style="height:10vh">
		<div class="col text-center">
        <p class="bi bi-caret-down display-3"></p> 
        </div>
</div>
</div>

<div class="b-example-divider"></div>

<div class="container-fluid" style="background-color:#101031">
<div class="container">
<!--	<h2 class="pb-2 border-bottom">Security aspects</h2> -->
	<div class="row g-5 py-5 row-cols-1 row-cols-lg-3">
	{% for entry in site.data.features %}
		<div class="col d-flex align-items-start p-3">
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
</div>

<div class="b-example-divider"></div>

<div class="container-fluid" style="background-color:#0A0A1E">
	<div class="container pt-5 pb-5 text-center">
		<h1 class="p-4">Screenshots</h1>
		<div id="screenshots" class="carousel slide">
			<div class="carousel-inner">
				{% assign screenshot_files = site.static_files | where: "screenshot", true %}
				{% for screenshot in screenshot_files %}
				<div class="carousel-item {% if forloop.first == true %} active {% endif %}">
					<img class="d-block w-100" src="{{ screenshot.path | remove_first: "/"}}">
				</div>
				{% endfor %}
			</div>
			<button class="carousel-control-prev" type="button" data-bs-target="#screenshots" data-bs-slide="prev">
				<span class="carousel-control-prev-icon" aria-hidden="true"></span>
				<span class="visually-hidden">Previous</span>
			</button>
			<button class="carousel-control-next" type="button" data-bs-target="#screenshots" data-bs-slide="next">
				<span class="carousel-control-next-icon" aria-hidden="true"></span>
				<span class="visually-hidden">Next</span>
			</button>

		</div>
	</div>
</div>
