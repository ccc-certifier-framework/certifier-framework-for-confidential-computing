#pragma once
#ifndef MPL_WRITE_QUEUE_HPP
#define MPL_WRITE_QUEUE_HPP

#include "buffer.hpp"
#include <array>
#include <deque>
#include <unistd.h>
#include <sys/uio.h>

namespace mpl {
    class WriteQueue {
        static constexpr int MAX_IOVS = 128;
        
        std::deque<Buffer> buffers_;
        std::vector<struct iovec> iovs_;
        
    public:
        inline bool empty() const {
            return buffers_.empty();
        }

        inline void push_back(Buffer&& buf) {
            buffers_.push_back(std::move(buf));
        }

        void writeTo(int socket);
    };

}

#endif
