#include "Health.hpp"

#include <drogon/HttpResponse.h>

namespace API {
using namespace drogon;

void Health::_health(const HttpRequestPtr & /*req*/, std::function<void(const HttpResponsePtr &)> &&callback) {
  Json::Value body;
  body["status"] = "ok";

  auto resp = HttpResponse::newHttpJsonResponse(body);
  resp->setStatusCode(HttpStatusCode::k200OK);
  callback(resp);
}

} // namespace API
