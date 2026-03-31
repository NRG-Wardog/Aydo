#pragma once

#include <drogon/HttpController.h>

namespace API {
using namespace drogon;

class Health : public HttpController<Health> {
public:
  METHOD_LIST_BEGIN
  METHOD_ADD(Health::_health, "/api/health", Get);
  METHOD_LIST_END

private:
  static void _health(const HttpRequestPtr &req,
                      std::function<void(const HttpResponsePtr &)> &&callback);
};

} // namespace API
