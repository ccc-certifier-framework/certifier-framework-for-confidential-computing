#include <jilog.hpp>
#include <mpl/buffer.hpp>
#include <mpl/write_queue.hpp>
#include <mpl/packet.hpp>
#include <mpl/syserr.hpp>
#include <mpl/demo/app_options.hpp>
#include <mpl/demo/se3_rigid_body_scenario.hpp>
#include <netdb.h>
#include <getopt.h>
#include <iostream>
#include <chrono>
#include <poll.h>

namespace mpl {
    class RobotClient {
        int socket_{-1};

        Buffer rBuf_{1024*4};
        WriteQueue writeQueue_;

    public:
        RobotClient() {
        }

        ~RobotClient() {
            if (socket_ != -1)
                ::close(socket_);
        }

        void connect(const std::string& host, int port) {
            struct addrinfo hints, *addrInfo;
            std::memset(&hints, 0, sizeof(hints));
            hints.ai_family = PF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_PASSIVE;

            std::string service = std::to_string(port);

            if (int err = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &addrInfo))
                throw std::invalid_argument("getaddrinfo failed: " + std::to_string(err));

            for (auto it = addrInfo ; it ; it = it->ai_next) {
                if ((socket_ = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol)) == -1) {
                    JI_LOG(INFO) << "failed to create socket: " << errno;
                } else if (::connect(socket_, it->ai_addr, it->ai_addrlen) == 0) {
                    JI_LOG(INFO) << "connected";
                    break;
                } else {
                    ::close(std::exchange(socket_, -1));
                }
            }

            if (socket_ == -1)
                JI_LOG(WARN) << "connect failed: " << errno;
        }

        void connect(const std::string& host) {
            auto i = host.find(':');
            if (i == std::string::npos) {
                connect(host, 0x415E);
            } else {
                connect(host.substr(0, i), std::stoi(host.substr(i+1)));
            }
        }

    private:
        void doRead() {
            assert(rBuf_.remaining() > 0); // we may need to grow the buffer

            ssize_t n = ::recv(socket_, rBuf_.begin(), rBuf_.remaining(), 0);
            if (n < 0)
                throw syserr("recv");
            if (n == 0) {
                ::close(std::exchange(socket_, -1));
                return;
            }

            rBuf_ += n;
            rBuf_.flip();
            std::size_t needed;
            while ((needed = packet::parse(rBuf_, [&] (auto&& pkt) {
                            process(std::forward<decltype(pkt)>(pkt));
                        })) == 0);
            rBuf_.compact(needed);
        }

        template <class T>
        void process(T&&) {
            JI_LOG(WARN) << "unexpected packet type: " << T::name();
        }

        void process(packet::Done&& pkt) {
            JI_LOG(INFO) << "Received DONE";
            ::close(std::exchange(socket_, -1));
        }

        template <class State>
        void process(packet::Path<State>&& pkt) {
            JI_LOG(INFO) << "Recieved path cost = " << pkt.cost() << ", elapsed millis = " << pkt.solveTimeMillis();
            for (auto& q : pkt.path())
                JI_LOG(INFO) << "  " << q;
        }

    public:
        // void sendProblem(int argc, char *argv[]) {
        //     writeQueue_.push_back(packet::Problem(argc, argv));
        // }

        void sendProblem(const demo::AppOptions& options) {
            writeQueue_.push_back(options.toProblemPacket());
        }

        void loop() {
            while (socket_ != -1) {
                struct pollfd pfd;
                pfd.fd = socket_;
                pfd.events = POLLIN;
                if (!writeQueue_.empty())
                    pfd.events |= POLLOUT;

                if (::poll(&pfd, 1, -1) == -1)
                    throw syserr("poll()");

                JI_LOG(TRACE) << "poll returned events: " << pfd.revents;

                if (pfd.revents & POLLOUT)
                    writeQueue_.writeTo(socket_);

                if (pfd.revents & POLLIN)
                    doRead();
            }
        }
    };
}

int main(int argc, char *argv[]) try {
    using Clock = std::chrono::steady_clock;
    using S = double;
    using Scenario = mpl::demo::SE3RigidBodyScenario<S>;
    using State = typename Scenario::State;
    using Bound = typename Scenario::Bound;

    auto start = Clock::now();
    
    mpl::demo::AppOptions options(argc, argv);

    // static const char opt[] = "--coordinator";

    // std::string coordinator;
    
    // for (int i=1 ; i<argc ; ++i) {
    //     char *arg = argv[i];
    //     if (std::strncmp(opt, arg, sizeof(opt)-1) == 0) {
    //         if (arg[sizeof(opt)-1] == '=')
    //             coordinator = arg+sizeof(opt);
    //         else if (arg[sizeof(opt)-1] == '\0' && i+1<argc)
    //             coordinator = argv[++i];
    //     }
    // }

    // if (coordinator.empty())
    //     throw std::invalid_argument("--coordinator is required");

    mpl::RobotClient robot;
    
    robot.connect(options.coordinator());
    // robot.sendProblem(argc, argv);
    robot.sendProblem(options);
    robot.loop();

    JI_LOG(INFO) << "robot total elapsed time: " << (Clock::now() - start);

    return EXIT_SUCCESS;
} catch (const std::exception& ex) {
    JI_LOG(FATAL) << "error: " << ex.what();
    return EXIT_FAILURE;
}
