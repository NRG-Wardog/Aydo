#pragma once

#include <drogon/HttpController.h>

#include "../Middleware/Auth.hpp"

namespace API {
using namespace drogon;

class Sandbox : public HttpController<Sandbox> {
public:
  METHOD_LIST_BEGIN

  METHOD_ADD(Sandbox::_requestFileScan, "/request-file-scan", Post, "Middleware::AuthFilter");
  METHOD_ADD(Sandbox::_uploadFile, "/upload-file", Post, "Middleware::AuthFilter");
  METHOD_ADD(Sandbox::_getScan, "/get-scan", Post, "Middleware::AuthFilter");

  METHOD_LIST_END

private:
  static void _requestFileScan(const HttpRequestPtr &req,
                               std::function<void(const HttpResponsePtr &)> &&callback);

  static void _uploadFile(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&callback);

  static void _getScan(const HttpRequestPtr &req,
                       std::function<void(const HttpResponsePtr &)> &&callback);
};
} // namespace API