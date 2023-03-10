#pragma once
#include <chrono>
#include <jsoncpp/json/reader.h>
#include <jsoncpp/json/value.h>
#include <memory>
#include <string>
#include <jwt-cpp/jwt.h>

class IdToken {
private:
  /* Issuer Identifier for the Issuer of the response. The iss value is a case
   * sensitive URL using the https scheme that contains scheme, host, and
   * optionally, port number and path components and no query or fragment
   * components. */
  std::shared_ptr<std::string> iss;
  /* Audience(s) that this ID Token is intended for. It MUST contain the
   * OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also
   * contain identifiers for other audiences. In the general case, the aud value
   * is an array of case sensitive strings. In the common special case when
   * there is one audience, the aud value MAY be a single case sensitive string.
   */
  std::shared_ptr<std::string> aud;
  /* Subject Identifier. A locally unique and never reassigned identifier within
   * the Issuer for the End-User, which is intended to be consumed by the
   * Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST
   * NOT exceed 255 ASCII characters in length. The sub value is a case
   * sensitive string.*/
  std::shared_ptr<std::string> sub;
  /* Expiration time on or after which the ID Token MUST NOT be accepted for
   * processing. The processing of this parameter requires that the current
   * date/time MUST be before the expiration date/time listed in the value.
   * Implementers MAY provide for some small leeway, usually no more than a few
   * minutes, to account for clock skew. Its value is a JSON number representing
   * the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the
   * date/time. See RFC 3339 [RFC3339] for details regarding date/times in
   * general and UTC in particular.*/
  std::shared_ptr<std::chrono::system_clock::time_point> exp;
  /* Time at which the JWT was issued. Its value is a JSON number
   * representing the number of seconds from 1970-01-01T0:0:0Z as measured in
   * UTC until the date/time. */
  std::shared_ptr<std::chrono::system_clock::time_point> iat;
  /* Time when the End-User authentication occurred. Its value is a JSON number
   * representing the number of seconds from 1970-01-01T0:0:0Z as measured in
   * UTC until the date/time. When a max_age request is made or when auth_time
   * is requested as an Essential Claim, then this Claim is REQUIRED; otherwise,
   * its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds to
   * the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)*/
  std::shared_ptr<std::chrono::system_clock::time_point> auth_time;

public:
  IdToken() = delete;
  /**
   * @brief Construct a new Id Token object
   *
   * @param iss Issuer Identifier
   * @param aud 	Audience
   * @param sub  Subject Identifier
   * @param expire Time in seconds after which the token MUST NOT be accepted
   * for processing
   * @param auth_time Time when the End-User authentication occurred
   */
  IdToken(std::shared_ptr<std::string> iss, std::shared_ptr<std::string> aud,
          std::shared_ptr<std::string> sub, const size_t expire,
          std::shared_ptr<std::chrono::system_clock::time_point> auth_time);
  /**
   * @brief Construct a JSON-object from the instances attributes
   *
   * @return std::shared_ptr<Json::Value>
   */
  std::shared_ptr<Json::Value> toJson();
  ~IdToken();
};