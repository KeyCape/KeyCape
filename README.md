# Overview
This project is an identity provider implemented in C++. It leverages the library `libwebauthn-cpp` to enable the usage of passwordless authentication.

Its main features are following:
* Open Id Connect V1(partially)
* WebAuthn
    * Credential registration
    * Login 
    * Registration of further credentials

# Prerequisites
The Server has been tested on **ubuntu:22.4**.
The following packages are required:

* `libjsoncpp-dev`
* `uuid-dev`
* `libssl-dev`
* `zlib1g-dev`
* `libmariadb-dev`
* `cmake`
* `make`
* `git`
* `gcc-12`
* `libhiredis-dev`
* `libgoogle-glog-dev`
* `python3-pip`

Furthermore [Drogon](https://github.com/drogonframework/drogon) has to be compiled with `C++20`.

# HTTPS endpoints
| Protokoll | | URI | Description |
|---|---|---|---|
|WebAuthn|Register|`/register/begin/{username}` | Initialize registration
|WebAuthn|Register|`/register/finish/{username}` | Finish registration
|WebAuthn|Login|`/login/begin/{username}` | Initialize login
|WebAuthn|Login|`/login/finish/{username}` | Finish login
||Status|`/session/status` | State of the session
||Logout|`/logout` | Logout
|Open Id Connect||`/oidc/clientRegister` | Register an application(owncloud, gitea)
|Open Id Connect||`/oidc/authorize` | Authorize request (Shows a button with the label *authorize*)
|Open Id Connect||`/oidc/grant` | Response to /oidc/authorize if the user authorizes the application 
|Open Id Connect||`/oidc/token` | Used by the application to get the Access Token
|Open Id Connect||`/oidc/userinfo` | Used by the application to get the ID-Token
|Open Id Connect||`/oidc/key` | Public key used for the signatures

# Quick start
Run the following command from the main directory.

```bash
docker build -t idp -f .docker/Dockerfile.demo ./
```

This builds a docker image with a running instance of the Server. 
Now cd into the directory `.docker` and run following command:

```bash
docker-compose up
```

Now open the following link:
[http://localhost](http://localhost)