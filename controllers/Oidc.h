#pragma once
#include <Challenge.h>
#include <CredentialRecord.h>
#include <IdToken.h>
#include <drogon/HttpController.h>
#include <forward_list>
#include <helper/response.h>
#include <string>

using namespace drogon;

class Oidc : public drogon::HttpController<Oidc> {
private:
  std::shared_ptr<std::string> iss; // Issuer Identifier
  std::shared_ptr<std::string> ecPubkey;
  std::shared_ptr<std::string> ecPrivkey;

  static auto generateResponseAuhtorizationCode(size_t &client_id,
                                                std::string &redirect_uri,
                                                size_t &resource_owner_id)
      -> Task<HttpResponsePtr>;

public:
  // The length in bytes of generated random bytes
  static const size_t tokenLen;
  static const size_t clientIdLen;
  static const size_t clientSecretLen;
  static const size_t idTokenExpire;     // In seconds
  static const size_t accessTokenExpire; // In seconds

  METHOD_LIST_BEGIN
  METHOD_ADD(
      Oidc::authorize,
      "authorize?response_type={1}&client_id={2}&redirect_uri={3}&scope={4}",
      Get);
  METHOD_ADD(Oidc::grant, "grant?token={1}", Post);
  METHOD_ADD(Oidc::clientRegister,
             "clientRegister?website_uri={1}&app_name={2}&client_type={3}&"
             "callback_uri={4}",
             Post);
  METHOD_ADD(Oidc::token,
             "token?grant_type={1}&code={2}&redirect_uri={3}&client_id={4}&"
             "client_secret={5}",
             Post);
  METHOD_ADD(Oidc::userinfo, "userinfo", Post);
  METHOD_ADD(Oidc::userinfo, "userinfo", Get);
  METHOD_LIST_END

  Oidc();

  drogon::AsyncTask
  authorize(HttpRequestPtr req,
            std::function<void(const HttpResponsePtr &)> callback,
            std::string response_type, std::string client_id,
            std::string redirect_uri, std::string scope);

  drogon::AsyncTask grant(HttpRequestPtr req,
                          std::function<void(const HttpResponsePtr &)> callback,
                          std::string token);
  /**
   * @brief 3.1.3. Token Endpoint
   *
   *  To obtain an Access Token, an ID Token, and optionally a Refresh Token,
   * the RP (Client) sends a Token Request to the Token Endpoint to obtain a
   * Token Response, as described in Section 3.2 of OAuth 2.0 [RFC6749], when
   * using the Authorization Code Flow.  Communication with the Token Endpoint
   * MUST utilize TLS. See Section 16.17 for more information on using TLS.
   *
   * See: https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   *
   * @param grant_type REQUIRED. Value MUST be set to "authorization_code".
   * @param code REQUIRED. The authorization code received from the
   * authorization server.
   * @param redirect_uri REQUIRED. The "redirect_uri" parameter was included
   * in the authorization request as described in Section 4.1.1, and their
   * values MUST be identical.
   * @param client_id REQUIRED. The client_id which got granted.
   * @param client_secret REQUIRED. The client_secret.
   */
  drogon::AsyncTask token(HttpRequestPtr req,
                          std::function<void(const HttpResponsePtr &)> callback,
                          std::string grant_type, std::string code,
                          std::string redirect_uri, std::string client_id,
                          std::string client_secret);
  /**
   * @brief Userinfo Endpoint
   * The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns
   * Claims about the authenticated End-User. To obtain the requested Claims
   * about the End-User, the Client makes a request to the UserInfo Endpoint
   * using an Access Token obtained through OpenID Connect Authentication. These
   * Claims are normally represented by a JSON object that contains a collection
   * of name and value pairs for the Claims. Communication with the UserInfo
   * Endpoint MUST utilize TLS. See Section 16.17 for more information on using
   * TLS.
   *
   * The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST
   * methods defined in RFC 2616 [RFC2616].
   *
   * The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token
   * Usage [RFC6750].
   *
   * The UserInfo Endpoint SHOULD support the use of Cross Origin Resource
   * Sharing (CORS) [CORS] and or other methods as appropriate to enable Java
   * Script Clients to access the endpoint.
   */
  drogon::AsyncTask
  userinfo(HttpRequestPtr req,
           std::function<void(const HttpResponsePtr &)> callback);

  drogon::AsyncTask
  clientRegister(HttpRequestPtr req,
                 std::function<void(const HttpResponsePtr &)> callback,
                 std::string website_uri, std::string app_name, int client_type,
                 std::string callback_ur);
};

// TODO: NEXT STEP: /token ENDPOINT!!