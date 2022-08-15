#include <jilog.hpp>
#include <mpl/write_queue.hpp>
#include <mpl/syserr.hpp>

void mpl::WriteQueue::writeTo(int socket) {
    if (empty())
        return;
    
    iovs_.clear();
    for (auto it = buffers_.begin() ; iovs_.size() < MAX_IOVS && it != buffers_.end() ; ++it) {
        iovs_.emplace_back();
        iovs_.back().iov_base = it->begin();
        iovs_.back().iov_len = it->remaining();
    }

    JI_LOG(TRACE) << "about to write " << iovs_.size() << " iovecs to " << socket;
    ssize_t n = ::writev(socket, iovs_.data(), iovs_.size());
    JI_LOG(TRACE) << "wrote " << n << " bytes to " << socket;
    if (n == -1) {
        if (errno == EAGAIN)
            return;
        throw syserr("writev");
    }

    while (n > 0) {
        if (n >= buffers_.front().remaining()) {
            n -= buffers_.front().remaining();
            buffers_.pop_front();
            JI_LOG(TRACE) << "removing completed buffer";
        } else {
            JI_LOG(TRACE) << "updating buffer in front";
            buffers_.front() += n;
            break;
        }
    }
}
