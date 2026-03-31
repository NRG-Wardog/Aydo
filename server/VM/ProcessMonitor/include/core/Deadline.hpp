#pragma once

#include <chrono>

class Deadline {
public:
  explicit Deadline(std::chrono::steady_clock::time_point tp) : m_tp(tp) {}

  static Deadline after(std::chrono::milliseconds dur) {
    return Deadline(std::chrono::steady_clock::now() + dur);
  }

  bool expired() const {
    return std::chrono::steady_clock::now() >= m_tp;
  }

  std::chrono::milliseconds remaining_ms() const {
    const auto now = std::chrono::steady_clock::now();
    if (now >= m_tp) {
      return std::chrono::milliseconds::zero();
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(m_tp - now);
  }

  std::chrono::steady_clock::time_point time_point() const {
    return m_tp;
  }

private:
  std::chrono::steady_clock::time_point m_tp;
};
