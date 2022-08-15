#pragma once
#ifndef MPL_COMM_HPP
#define MPL_COMM_HPP

#include <string>
#include <netdb.h>
#include "write_queue.hpp"
#include "packet.hpp"
#include "syserr.hpp"

namespace mpl {
    class Comm {
        static constexpr int DEFAULT_PORT = 0x415E;

        enum {
            DISCONNECTED,
            CONNECTING,
            CONNECTED,
        };

        int state_{DISCONNECTED};
        int done_{false};
        int socket_{-1};
        
        struct addrinfo *addrInfo_{nullptr};
        struct addrinfo *connectAddr_{nullptr};

        Buffer rBuf_{4*1024};
        WriteQueue writeQueue_;

        std::uint64_t problemId_{0};
        
        void close();
        void connected();
        void tryConnect();

        template <class T>
        void handle(T&&) {
            JI_LOG(WARN) << "unexpected packet type received: " << T::name();
        }

        void handle(packet::Done&&);
        
        bool finishConnect();

        template <class PacketFn>
        void processImpl(PacketFn);

    public:
        ~Comm();

        void setProblemId(std::uint64_t id) {
            problemId_ = id;
        }

        inline operator bool () const {
            return socket_ != -1;
        }

        void connect(const std::string& host);
        void connect(const std::string& host, int port);
        void process();
        template <class PathFn>
        void process(PathFn);

        template <class S, class Rep, class Period>
        void sendPath(S cost, std::chrono::duration<Rep, Period> elapsed, std::vector<std::tuple<Eigen::Quaternion<S>, Eigen::Matrix<S, 3, 1>>>&& path);
        template <class S, class Rep, class Period, int dim>
        void sendPath(S cost, std::chrono::duration<Rep, Period> elapsed, std::vector<Eigen::Matrix<S, dim, 1>>&& path);
        
        void sendDone();

        inline bool isDone() {
            return done_;
        }
    };

}

template <class S, class Rep, class Period>
void mpl::Comm::sendPath(
    S cost,
    std::chrono::duration<Rep, Period> elapsed,
    std::vector<std::tuple<Eigen::Quaternion<S>, Eigen::Matrix<S, 3, 1>>>&& path)
{
    if (socket_ == -1)
        return;

    using State = std::tuple<Eigen::Quaternion<S>, Eigen::Matrix<S, 3, 1>>;
    std::uint32_t elapsedMillis = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    writeQueue_.push_back(packet::Path<State>(cost, elapsedMillis, std::move(path)));
}

template <class S, class Rep, class Period, int dim>
void mpl::Comm::sendPath(
    S cost,
    std::chrono::duration<Rep, Period> elapsed,
    std::vector<Eigen::Matrix<S, dim, 1>>&& path)
{
    if (socket_ == -1)
        return;

    using State = Eigen::Matrix<S, dim, 1>;
    std::uint32_t elapsedMillis = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    writeQueue_.push_back(packet::Path<State>(cost, elapsedMillis, std::move(path)));
}
    

template <class PacketFn>
void mpl::Comm::processImpl(PacketFn fn) {
    ssize_t n;
    std::size_t needed;
    
    switch (state_) {
    case DISCONNECTED:
        return;
    case CONNECTING:
        if (!finishConnect())
            return;
        // after connecting, fall through to the connected case.
    case CONNECTED:
        if (!writeQueue_.empty())
            writeQueue_.writeTo(socket_);

        if ((n = ::recv(socket_, rBuf_.begin(), rBuf_.remaining(), 0)) < 0) {
            if (errno == EAGAIN || errno == EINTR)
                return;
            done_ = true;
            throw syserr("recv");
        }
        
        if (n == 0) {
            JI_LOG(TRACE) << "connection closed";
            close();
            // for now, if the connection was established but then
            // closes, we mark this process as done.  The thought
            // being that if we continue processing and fine a
            // solution, we have nothing to communicate it to.  In the
            // future it may make sense to try to reconnect to the
            // coordinator before giving up (depending on how flakey
            // connections are).  If we do change the behavior, we'll
            // have to think through what to do when there is a
            // connection error too.
            done_ = true;
            state_ = DISCONNECTED;
            break;
        }

        rBuf_ += n;
        rBuf_.flip();
        while ((needed = packet::parse(rBuf_, fn)) == 0);
        rBuf_.compact(needed);
        break;
    default:
        JI_LOG(FATAL) << "in bad state: " << state_;
        abort();
    }
}

template <class PathFn>
void mpl::Comm::process(PathFn fn) {
    processImpl([&] (auto&& pkt) {
        using T = std::decay_t<decltype(pkt)>;
        if constexpr (packet::is_path<T>::value) {
            fn(pkt.cost(), std::move(pkt).path());
        } else {
            handle(std::forward<decltype(pkt)>(pkt));
        }
    });
}

#endif
