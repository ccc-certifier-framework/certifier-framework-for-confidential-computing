#include <mpl/comm.hpp>
#include <mpl/packet.hpp>
#include <jilog.hpp>
#include <algorithm>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>



mpl::Comm::~Comm() {
    close();

    if (addrInfo_)
        ::freeaddrinfo(std::exchange(addrInfo_, nullptr));
}

void mpl::Comm::close() {
    if (socket_ != -1) {
        JI_LOG(TRACE) << "closing socket " << socket_;
        if (::close(std::exchange(socket_, -1)) == -1)
            JI_LOG(WARN) << "error closing socket: " << errno;
    }
}

void mpl::Comm::connected() {
    state_ = CONNECTED;
    JI_LOG(INFO) << "connected";

    writeQueue_.push_back(packet::Hello(problemId_));
}

void mpl::Comm::tryConnect() {
    JI_LOG(INFO) << "trying to connect";
    char name[INET6_ADDRSTRLEN];
    

    return;





    while (connectAddr_ != nullptr) {
        if ((socket_ = ::socket(connectAddr_->ai_family, connectAddr_->ai_socktype, connectAddr_->ai_protocol)) == -1) {
            JI_LOG(INFO) << "failed to create socket (" << errno << ")";
        } else {
            int nonBlocking = 0;
            //if (::ioctl(socket_, SOCK_NONBLOCK, reinterpret_cast<char*>(&nonBlocking)) == -1)
            //    JI_LOG(INFO) << "set non-blocking failed (" << errno << ")";

            if (connectAddr_->ai_family == AF_INET || connectAddr_->ai_family == AF_INET6) {
                inet_ntop(
                    connectAddr_->ai_family,
                    &reinterpret_cast<struct sockaddr_in*>(connectAddr_->ai_addr)->sin_addr,
                    name, sizeof(name));
                JI_LOG(INFO) << "connecting to " << name;
            }
            
            if (::connect(socket_, connectAddr_->ai_addr, connectAddr_->ai_addrlen) == 0) {
                connected();
                return;
            }
        
            if (errno == EINPROGRESS) {
                state_ = CONNECTING;
                JI_LOG(INFO) << "non-blocking connection in progress";
                return;
            }
        
            JI_LOG(INFO) << "connect failed: " << errno;
            close();
        }
    }

    state_ = DISCONNECTED;
}

void mpl::Comm::connect(const std::string& host) {
    auto i = host.find(':');
    if (i == std::string::npos)
        connect(host, DEFAULT_PORT);
    else
        connect(host.substr(0, i), std::stoi(host.substr(i+1)));
}

void mpl::Comm::connect(const std::string& host, int port) {
    JI_LOG(INFO) << "connecting to [" << host << "], port " << port;
    
    if (addrInfo_)
        ::freeaddrinfo(std::exchange(addrInfo_, nullptr));
    

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    

    std::string service = std::to_string(port);

    if (int err = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &addrInfo_))
        throw std::invalid_argument("getaddrinfo failed with error: " + std::to_string(err));

    connectAddr_ = addrInfo_;

    tryConnect();
}

bool mpl::Comm::finishConnect() {
    struct pollfd pfd;

    pfd.fd = socket_;
    pfd.events = POLLOUT;
    if (::poll(&pfd, 1, 0) == -1) {
        JI_LOG(WARN) << "poll failed while waiting for connection (" << errno << ")";
        return false;
    }

    // nothing changed on the descriptor
    if (pfd.revents == 0)
        return false;
    
    if (pfd.revents & (POLLHUP | POLLERR)) {
        JI_LOG(WARN) << "connection failed, trying next address";
        connectAddr_ = connectAddr_->ai_next;
        tryConnect();
        return false;
    }
    
    if ((pfd.revents & POLLOUT) == 0) {
        JI_LOG(WARN) << "unhandled events: " << pfd.revents;
        return false;
    }
        
    connected();
    return true;
}

void mpl::Comm::process() {
    processImpl([&] (auto&& pkt) { handle(std::forward<decltype(pkt)>(pkt)); });
}


void mpl::Comm::handle(packet::Done&&) {
    JI_LOG(INFO) << "received DONE";
    done_ = true;
}

void mpl::Comm::sendDone() {
    if (socket_ == -1 || state_ != CONNECTED)
        return;

    int nonBlocking = 0;
    if (::ioctl(socket_, SOCK_NONBLOCK, reinterpret_cast<char*>(&nonBlocking)) == -1)
        JI_LOG(INFO) << "set blocking failed (" << errno << ")";

    writeQueue_.push_back(packet::Done(problemId_));
    while (!writeQueue_.empty())
        writeQueue_.writeTo(socket_);
}

