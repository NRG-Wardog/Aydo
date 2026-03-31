#pragma once
#include <krabs.hpp>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include "pch.h"
#include <nlohmann/json.hpp>

#include <fstream>
#include <functional>
#include <mutex>
#include <string>

#include "Deadline.hpp"

class KernelBlock {
public:
  explicit KernelBlock(const std::wstring &userSessionName);
  using Callback = std::function<void(const EVENT_RECORD &, const krabs::trace_context &)>;

  void addDefaultKernelProviders();
  template <class Prov, class... Args>
  void addProvider(Args &&...args) {
    m_provs.emplace_back(std::make_unique<KProv<Prov>>(std::forward<Args>(args)...));
  }

  void start(const Callback &cb);
  void stop();
  // Stop with deadline; may detach worker thread if it exceeds deadline.
  bool stopWithDeadline(const Deadline &deadline);

private:
  std::unique_ptr<krabs::kernel_trace> m_trace;

  struct IKernelProv {
    virtual ~IKernelProv() = default;
    virtual void _attach(krabs::kernel_trace &tr, const Callback &cb) = 0;
  };

  template <class Prov>
  struct KProv : IKernelProv {
    Prov p;
    template <class... Args>
    explicit KProv(Args &&...args)
        : p(std::forward<Args>(args)...) {}
    void _attach(krabs::kernel_trace &tr, const Callback &cb) override {
      p.add_on_event_callback(cb);
      tr.enable(p);
    }
  };

  std::vector<std::unique_ptr<IKernelProv>> m_provs;
  std::thread m_thread;
  std::wstring m_sessionName;
  Callback m_cb;
};
