#include "ringbuf.h"
#include <stdlib.h>
#include <string.h>
#include <new>

using namespace std;

ringbuf::ringbuf(size_t length) : length(length) {
    data = (uint8_t*)malloc(length);
    if (!data)
        throw bad_alloc();
}

ringbuf::~ringbuf() {
    free(data);
}

void ringbuf::peek(span<uint8_t> sp) {
    size_t to_copy = min(sp.size(), length - offset);

    memcpy(sp.data(), data + offset, to_copy);

    if (sp.size() == to_copy)
        return;

    sp = sp.subspan(to_copy);

    memcpy(sp.data(), data, sp.size());
}

void ringbuf::discard(size_t bytes) {
    offset += bytes;
    offset %= length;
    used -= bytes;
}

void ringbuf::read(span<uint8_t> sp) {
    peek(sp);
    discard(sp.size());
}

void ringbuf::write(span<const uint8_t> sp) {
    size_t to_copy = min(sp.size(), length - offset);

    memcpy(data + offset + used, sp.data(), to_copy);
    used += sp.size();

    if (sp.size() == to_copy)
        return;

    sp = sp.subspan(to_copy);

    memcpy(data, sp.data(), sp.size());
}

size_t ringbuf::size() const {
    return used;
}

size_t ringbuf::available() const {
    return length - used;
}

bool ringbuf::empty() const {
    return used == 0;
}

void ringbuf::clear() {
    used = 0;
}
