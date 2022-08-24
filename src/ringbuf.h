#pragma once

#include <stdint.h>
#include <stddef.h>
#include <span>

class ringbuf {
public:
    ringbuf(size_t length);
    ~ringbuf();
    void read(std::span<uint8_t> sp);
    void peek(std::span<uint8_t> sp);
    void write(std::span<const uint8_t> sp);
    void discard(size_t bytes);
    size_t size();
    size_t available();
    [[nodiscard]] bool empty();

private:
    uint8_t* data;
    size_t length;
    size_t offset = 0;
    size_t used = 0;
};
