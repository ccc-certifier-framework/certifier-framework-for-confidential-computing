#include <jilog.hpp>
#include <mpl/buffer.hpp>
#include <mpl/write_queue.hpp>
#include <mpl/packet.hpp>
#include <mpl/syserr.hpp>
#include <chrono>
#include <list>
#include <unordered_map>
#include <vector>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if HAS_AWS_SDK
#include <aws/lambda-runtime/runtime.h>
#include <aws/core/Aws.h>
#include <aws/core/utils/Outcome.h>
#include <aws/lambda/LambdaClient.h>
#include <aws/lambda/model/InvokeRequest.h>
#include <aws/core/utils/json/JsonSerializer.h>
#endif

namespace mpl {
    // template <class S>
    // std::pair<int, int> launchLambda(std::uint64_t pId, packet::ProblemSE3<S>& prob);

    enum LambdaType {
	LAMBDA_PSEUDO,
	LAMBDA_AWS,
	LAMBDA_SSH,
    };

    using ID = std::uint64_t;

    class Connection;
    
    class GroupData {
        Connection* initiator_;
        std::uint8_t algorithm_;
        bool done_{false};
        std::list<Connection*> connections_;
        
    public:
        GroupData(Connection* initiator, std::uint8_t algorithm)
            : initiator_(initiator)
            , algorithm_(algorithm)
        {
        }

        bool isDone() const {
            return done_;
        }

        void done() {
            done_ = true;
        }

        std::uint8_t algorithm() const {
            return algorithm_;
        }

        Connection* initiator() {
            return initiator_;
        }

        auto& connections() {
            return connections_;
        }
    };

    class Coordinator {
	int port_{0x415E};
        int listen_{-1};
	
	std::string sshIdentity_;
	std::vector<std::string> sshServers_;
	unsigned lambdaNo_{0};

	LambdaType lambdaType_{LAMBDA_PSEUDO};
	
        using Group = std::pair<const ID, GroupData>;
        
        ID nextGroupId_{static_cast<ID>(std::chrono::system_clock::now().time_since_epoch().count())};

        std::list<Connection> connections_;
        std::list<std::pair<int, int>> childProcesses_;
        std::unordered_map<ID, GroupData> groups_;

#if HAS_AWS_SDK
	static constexpr const char* ALLOCATION_TAG = "mplLambdaAWS";
        std::shared_ptr<Aws::Lambda::LambdaClient> lambdaClient_;
#endif

	std::pair<int, int> launchPseudoLambda(std::uint64_t pId, packet::Problem& prob);
	void launchAWSLambda(std::uint64_t pId, packet::Problem& prob);
	
	static void usage(const char*);
    public:
	Coordinator(int argc, char *argv[]) {
	    static struct option longopts[] = {
		{ "port", required_argument, 0, 'p' },
		{ "lambda-type", required_argument, 0, 'l' },
		{ "ssh", required_argument, 0, 's' },
		
		{ NULL, 0, NULL, 0 }
	    };

	    for (int ch ; (ch = ::getopt_long(argc, argv, "p:l:s:i:", longopts, NULL)) != -1 ; ) {
		char *endp;
		switch (ch) {
		case 'p':
		    port_ = (int)std::strtol(optarg, &endp, 10);
		    if (endp == optarg || *endp || port_ < 0)
			throw std::invalid_argument("bad port number");
		    break;
		case 'l':
		    if (std::strcmp("aws", optarg) == 0 ||
			std::strcmp("AWS", optarg) == 0)
			lambdaType_ = LAMBDA_AWS;
		    else if (std::strcmp("pseudo", optarg) == 0)
			lambdaType_ = LAMBDA_PSEUDO;
		    else if (std::strcmp("ssh", optarg) == 0)
			lambdaType_ = LAMBDA_SSH;
		    else
			throw std::invalid_argument("bad lambda type");
		    break;
		case 'i':
		    sshIdentity_ = optarg;
		    break;
		case 's':
                    std::clog << "adding server: " << optarg << std::endl;
		    sshServers_.push_back(optarg);
		    break;
		default:
		    usage(argv[0]);
		    throw std::invalid_argument("see above: " + std::to_string(ch));
		}
	    }
	}

	~Coordinator() {
            if (listen_ != -1 && !::close(listen_))
                JI_LOG(WARN) << "failed to close listening socket";
	    
#if HAS_AWS_SDK
	    if (lambdaType_ == LAMBDA_AWS) {
		Aws::SDKOptions options;
		Aws::ShutdownAPI(options);
	    }
#endif
        }

	void start() {
	    if ((listen_ = ::socket(PF_INET, SOCK_STREAM, 0)) == -1)
                throw syserr("socket()");

            int on = 1;
            if (::setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
                throw syserr("set reuse addr");
            
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(port_);
            
            if (::bind(listen_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1)
                throw syserr("bind()");

            socklen_t addrLen = sizeof(addr);
            if (::getsockname(listen_, reinterpret_cast<struct sockaddr*>(&addr), &addrLen) == -1)
                throw syserr("getsockname()");

            JI_LOG(INFO) << "listening on port: " << ntohs(addr.sin_port);
            
            if (::listen(listen_, 100) == -1)
                throw syserr("listen()");

#if HAS_AWS_SDK
	    if (lambdaType_ == LAMBDA_AWS) {
		JI_LOG(INFO) << "initializing lambda client";
		Aws::SDKOptions options;
		Aws::InitAPI(options);
		Aws::Client::ClientConfiguration clientConfig;
		clientConfig.region = "us-west-2";
		lambdaClient_ = Aws::MakeShared<Aws::Lambda::LambdaClient>(ALLOCATION_TAG, clientConfig);
	    }
#endif
            JI_LOG(INFO) << "next group ID will be " << nextGroupId_;
        }
        
        int accept(struct sockaddr *addr, socklen_t * addrLen) {
            return ::accept(listen_, addr, addrLen);
        }

        void loop();

        void launchLambdas(ID groupId, packet::Problem&& prob);
        
        ID createGroup(Connection* initiator, std::uint8_t algorithm);
        ID addToGroup(ID id, Connection* conn);
        void done(ID group, Connection* conn);

        template <class State>
        void gotPath(ID group, packet::Path<State>&& pkt, Connection* conn);
        // template <class T>
        // void broadcast(T&& packet, Group* group, Connection* conn);
    };

    class Connection {
        Coordinator& coordinator_;
        
        struct sockaddr_in addr_;
        socklen_t addrLen_{sizeof(addr_)};
        
        int socket_{-1};

        Buffer rBuf_{1024*4};
        WriteQueue writeQueue_;

        ID groupId_{0};
        // Group* group_{nullptr};

        bool doRead() {
            assert(rBuf_.remaining() > 0); // we may need to grow the buffer
            
            ssize_t n = ::recv(socket_, rBuf_.begin(), rBuf_.remaining(), 0);
            JI_LOG(TRACE) << "recv " << n;
            if (n <= 0) {
                // on error (-1) or connection close (0), send DONE to
                // the group to which this connection is attached.
                if (groupId_) {
                    coordinator_.done(groupId_, this);
                    groupId_ = 0;
                }
                
                return (n < 0) ? throw syserr("recv") : false;
            }

            rBuf_ += n;
            rBuf_.flip();
            // call the appropriate process overload for each packet
            // that arrives
            std::size_t needed;
            while ((needed = packet::parse(rBuf_, [&] (auto&& pkt) {
                            process(std::forward<decltype(pkt)>(pkt));
                        })) == 0);
            rBuf_.compact(needed);
            return true;
        }

        void process(packet::Hello&& pkt) {
            JI_LOG(INFO) << "got HELLO (id=" << pkt.id() << ")";
            groupId_ = coordinator_.addToGroup(pkt.id(), this);
            // this is a possible sign that the group already ended
            // before this connection arrived.  Respond with DONE.
            if (groupId_ == 0)
                writeQueue_.push_back(packet::Done(pkt.id()));
        }

        void process(packet::Done&& pkt) {
            JI_LOG(INFO) << "got DONE (id=" << pkt.id() << ")";
            if (groupId_ == 0 || groupId_ != pkt.id()) {
                JI_LOG(WARN) << "DONE group id mismatch";
            } else {
                coordinator_.done(groupId_, this);
                groupId_ = 0;
            }
        }

        void process(packet::Problem&& pkt) {
            JI_LOG(INFO) << "got Problem from " << socket_;

            // if this connection is connected to a group, send DONE
            // to that group before starting a new group.
            if (groupId_) {
                coordinator_.done(groupId_, this);
                groupId_ = 0;
            }
            
            groupId_ = coordinator_.createGroup(this, pkt.algorithm());
            coordinator_.launchLambdas(groupId_, std::move(pkt));
        }

        template <class State>
        void process(packet::Path<State>&& pkt) {
            JI_LOG(INFO) << "got Path " << sizeof(State);
            for (auto& q : pkt.path())
                JI_LOG(TRACE) << "  " << q;

            if (groupId_ == 0) {
                JI_LOG(WARN) << "got PATH without active group";
            } else {
                coordinator_.gotPath(groupId_, std::move(pkt), this);
            }
            // if (group_->second.algorithm() == 'r') {
            //     // for RRT we only send the path to the initiator
            //     group_->second.initiator()->write(std::move(pkt));
            // } else {
            //     // for C-FOREST we send broadcast to path
            //     coordinator_.broadcast(std::move(pkt), group_, this);
            // }
        }
        
    public:
        explicit Connection(Coordinator& coordinator)
            : coordinator_(coordinator)
            , socket_(coordinator.accept(reinterpret_cast<struct sockaddr*>(&addr_), &addrLen_))
        {
            JI_LOG(TRACE) << "connection accepted";
        }
        
        ~Connection() {
            if (groupId_) {
                coordinator_.done(groupId_, this);
                groupId_ = 0;
            }
            
            JI_LOG(TRACE) << "closing connection";
            if (socket_ != -1 && ::close(socket_) == -1)
                JI_LOG(WARN) << "connection close error: " << errno;
        }
        
        operator bool () const {
            return socket_ != -1;
        }

        operator struct pollfd () const {
            return { socket_, static_cast<short>(writeQueue_.empty() ? POLLIN : (POLLIN | POLLOUT)), 0 };
        }

        void degroup() {
            groupId_ = 0;
        }

        template <class Packet>
        void write(Packet&& packet) {
            writeQueue_.push_back(std::forward<Packet>(packet));
        }

        bool process(const struct pollfd& pfd) {
            try {
                if ((pfd.revents & POLLIN) && !doRead())
                    return false;

                if (pfd.revents & POLLOUT)
                    writeQueue_.writeTo(socket_);

                return true;
            } catch (const std::exception& ex) {
                JI_LOG(WARN) << "exception processing connection: " << ex.what();
                return false;
            }
        }
    };

    template <class ... T>
    std::string to_string(T&& ... args) {
        std::ostringstream str;
        (str << ... << std::forward<T>(args));
        return str.str();
    }
}

void mpl::Coordinator::usage(const char *argv0) {
    std::clog << "Usage: " << argv0 << "[options]\n"
	"Options:\n"
	" -p, --port=PORT          port on which to listen for lambdas\n"
	" -l, --lambda-type=TYPE   type of lambda to invoke (pseudo, aws, ssh)\n"
	" -s, -ssh=SERVER          adds a server to the list of servers to round-robin for ssh\n"
	"                          These can be `user@hostname` or just `hostname`.\n"
	"                          (use -s multiple times to add multiple servers)\n"
	" -i IDENTITY              ssh identity file to use"
	      << std::endl;
}

void mpl::Coordinator::launchAWSLambda(std::uint64_t pId, packet::Problem& prob) {
#if !HAS_AWS_SDK
    throw std::invalid_argument("AWS SDK is not available");
#else
    Aws::Lambda::Model::InvokeRequest invokeRequest;
    invokeRequest.SetFunctionName("mpl_lambda_aws_test");
    invokeRequest.SetInvocationType(Aws::Lambda::Model::InvocationType::Event);
    std::shared_ptr<Aws::IOStream> payload = Aws::MakeShared<Aws::StringStream>("PayloadData");
    Aws::Utils::Json::JsonValue jsonPayload;

    std::string pIdStr = std::to_string(pId);
    jsonPayload.WithString("problem-id", Aws::String(pIdStr.c_str(), pIdStr.size()));
    jsonPayload.WithString("algorithm", prob.algorithm() == 'r' ? "rrt" : "cforest");
    for (std::size_t i=0 ; i+1<prob.args().size() ; i+=2) {
	const std::string& key = prob.args()[i];
	const std::string& val = prob.args()[i+1];
	jsonPayload.WithString(
	    Aws::String(key.c_str(), key.size()),
	    Aws::String(val.c_str(), val.size()));
    }

    *payload << jsonPayload.View().WriteReadable();
    invokeRequest.SetBody(payload);
    invokeRequest.SetContentType("application/json");

    auto outcome = lambdaClient_->Invoke(invokeRequest);
    if (outcome.IsSuccess()) {
        auto &result = outcome.GetResult();
        Aws::IOStream& payload = result.GetPayload();
        Aws::String functionResult;
        std::getline(payload, functionResult);
	JI_LOG(INFO) << "Lambda result: " << functionResult;
    } else {
        auto &error = outcome.GetError();
	std::ostringstream msg;
	msg << "name: '" << error.GetExceptionName() << "', message: '" << error.GetMessage() << "'";
	throw std::runtime_error(msg.str());
	    
    }
#endif
}


// returns a pair of process-id and pipe-fd associated with the
// child process
std::pair<int, int> mpl::Coordinator::launchPseudoLambda(std::uint64_t pId, packet::Problem& prob) {
    // static const std::string resourceDirectory = "../../resources/";
    int lambdaId = lambdaNo_++;

    // We create a pipe solely for tracking when a child process
    // terminates.  When the child terminates, it will
    // automatically close its end of the pipe, causing a POLLHUP
    // event in the poll() loop.
    int p[2];
    if (::pipe(p) == -1)
        throw syserr("pipe");
    
    if (int pid = ::fork()) {
        // parent process
        ::close(p[1]);
        return { pid, p[0] };
    }
    
    // child process
    ::close(p[0]);
    
    // child process
    // Eigen::IOFormat fmt(Eigen::FullPrecision, Eigen::DontAlignCols, ",", ",", "", "", "", "");
    
    std::string program;
    
    // use a vector of string to make sure we have valid pointers to
    // strings for argv
    std::vector<std::string> args;

    if (lambdaType_ == LAMBDA_PSEUDO) {
	args.reserve(prob.args().size() + 6);
	
	program = "./mpl_lambda_pseudo";
	args.push_back(program); // argv[0] needs to be the program name
    } else {
	args.reserve(prob.args().size() + 10);
	program = "/usr/bin/ssh";
	args.push_back(program);
	if (!sshIdentity_.empty()) {
	    args.push_back("-i");
	    args.push_back(sshIdentity_);
	}
	// round-robin through server list
	args.push_back(sshServers_[lambdaId % sshServers_.size()]);
	args.push_back("./projects/mplambda/build/Lambda/mpl_lambda_pseudo");
    }

    args.push_back("-I"); // then add the group identifier
    args.push_back(std::to_string(pId));
    args.push_back("--algorithm");
    args.push_back(prob.algorithm() == 'r' ? "rrt" : "cforest");
    for (std::size_t i=0 ; i+1<prob.args().size() ; i+=2)
        args.push_back("--" + prob.args()[i] + "=" + prob.args()[i+1]);

    // command is for debugging
    std::ostringstream command;
    // build the argv char* array
    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& arg : args) {
        command << " " << arg;
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr); // <-- required terminator
    
    char file[20];
    snprintf(file, sizeof(file), "lambda-%04d.out", lambdaId);
    
    JI_LOG(TRACE) << "Running " << file << ":" << command.str();
    
    int fd = ::open(file, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    dup2(fd, 1); // make stdout write to file
    dup2(fd, 2); // make stderr write to file
    close(fd); // close fd, dups remain open
    
    execv(program.c_str(), const_cast<char*const*>(argv.data()));
    
    // if exec returns, then there was a problem
    throw syserr("exec");
}

auto mpl::Coordinator::createGroup(Connection* initiator, std::uint8_t algorithm) -> ID{
    ID id = nextGroupId_++;
    auto [ it, inserted ] = groups_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(id),
        std::forward_as_tuple(initiator, algorithm));
    assert(inserted);
    JI_LOG(INFO) << "starting new group " << it->first;
    return id;
}

auto mpl::Coordinator::addToGroup(ID id, Connection* conn) -> ID {
    auto it = groups_.find(id);
    if (it == groups_.end() || it->second.isDone())
        return 0;
    
    it->second.connections().push_back(conn);
    return it->first;
}

void mpl::Coordinator::done(ID groupID, Connection* conn) {
    auto group = groups_.find(groupID);
    if (group == groups_.end()) {
        JI_LOG(WARN) << "bad group on DONE: " << groupID;
        return;
    }
    
    auto& connections = group->second.connections();

    // when we get a DONE packet, broadcast DONE to all other
    // connections and mark the group as done.  We broadcast only on
    // the first DONE, but remove the connection from the group in any
    // case.
    for (auto it = connections.begin() ; it != connections.end() ; ) {
        if (*it == conn) {
            it = connections.erase(it);
        } else {
            if (!group->second.isDone())
                (*it)->write(packet::Done(group->first));
            ++it;
        }
    }
    group->second.done();

    // if we're DONE and have no remaining connections, we send DONE
    // to the initiator.
    if (connections.empty()) {
        JI_LOG(INFO) << "no remaining connections in group, sending DONE to initiator";
        group->second.initiator()->write(packet::Done(group->first));
    }

    // if there are no more connections, or the initiator caused the
    // DONE (from a new problem), then we remove the group.
    if (connections.empty() || group->second.initiator() == conn) {
        JI_LOG(INFO) << "removing group " << group->first;
        for (auto it = connections.begin() ; it != connections.end() ; ++it)
            (*it)->degroup();
                
        auto it = groups_.find(group->first);
        if (it != groups_.end())
            groups_.erase(it);
    }
}

template <class State>
void mpl::Coordinator::gotPath(ID groupID, packet::Path<State>&& packet, Connection* conn) {
    auto it = groups_.find(groupID);
    if (it == groups_.end()) {
        JI_LOG(WARN) << "invalid group: " << groupID;
        return;
    }

    it->second.initiator()->write(packet);
    // for RRT, only send the path to the initiator (above)
    if (it->second.algorithm() != 'r') {
        // for C-FOREST send the path to everyton
        for (auto* c : it->second.connections())
            if (conn != c)
                c->write(packet);
    }
}

void mpl::Coordinator::launchLambdas(ID groupId, packet::Problem&& prob) {
    unsigned nLambdas = prob.jobs();
    if (lambdaType_ != LAMBDA_AWS) {
	for (unsigned i=0 ; i<nLambdas ; ++i)
	    childProcesses_.emplace_back(launchPseudoLambda(groupId, prob));
    } else {
	for (unsigned i=0 ; i<nLambdas ; ++i)
	    launchAWSLambda(groupId, prob);
    }
}

void mpl::Coordinator::loop() {
    std::vector<struct pollfd> pfds;

    for (;;) {
        pfds.clear();

        // first comes the fds of the child processes (note that
        // connection processing may change the child process list, so
        // this must be processed first)
        for (auto [ pid, fd ] : childProcesses_) {
            pfds.emplace_back();
            pfds.back().fd = fd;
            pfds.back().events = POLLIN;
        }

        // then et of pollfds is 1:1 with connections
        for (Connection& conn : connections_)
            pfds.emplace_back(conn);

        // then comes the accepting socket
        pfds.emplace_back();
        pfds.back().fd = listen_;
        pfds.back().events = POLLIN;

        JI_LOG(TRACE) << "polling " << pfds.size();
        int nReady = ::poll(pfds.data(), pfds.size(), -1);

        JI_LOG(TRACE) << "poll returned " << nReady;
        
        if (nReady == -1) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            throw syserr("poll");
        }

        auto pit = pfds.begin();
        for (auto cit = childProcesses_.begin() ; cit != childProcesses_.end() ; ++pit) {
            assert(pit != pfds.end());
            
            if ((pit->revents & POLLHUP) == 0) {
                ++cit;
            } else {
	        int stat = 0;
                // if (::waitpid(cit->first, &stat, 0) == -1)
                //     JI_LOG(WARN) << "waitpid failed with error: " << errno;
                if (::close(cit->second) == -1)
                    JI_LOG(WARN) << "close failed with error: " << errno;
                JI_LOG(INFO) << "child process " << cit->first << " exited with status " << stat;
                
                cit = childProcesses_.erase(cit);
            }
        }

        for (auto cit = connections_.begin() ; cit != connections_.end() ; ++pit) {
            assert(pit != pfds.end());
            
            if (cit->process(*pit))
                ++cit;
            else
                cit = connections_.erase(cit);
        }
        
        assert(pit+1 == pfds.end());
        
        if (pit->revents & (POLLERR | POLLHUP))
            break;
        if (pit->revents & POLLIN) {
            connections_.emplace_back(*this);
            if (!connections_.back()) {
                JI_LOG(WARN) << "accept failed with error: " << errno;
                connections_.pop_back();
            }
            // struct sockaddr_in addr;
            // socklen_t addLen = sizeof(addr);
            
            // int fd = ::accept(listen, &addr, &addrLen);
            // if (fd != -1)
            //     connections.emplace_back(socket_);
            // && !connections.emplace_back(listen_))
            // connections.pop_back();
        }
    }
}


int main(int argc, char *argv[]) try {
    mpl::Coordinator coordinator(argc, argv);
    coordinator.start();
    coordinator.loop();
    return EXIT_SUCCESS;
} catch (const std::invalid_argument& ex) {
    std::clog << ex.what() << std::endl;
    return EXIT_FAILURE;
} catch (const std::exception& ex) {
    std::clog << ex.what() << std::endl;
    return EXIT_FAILURE;
}
