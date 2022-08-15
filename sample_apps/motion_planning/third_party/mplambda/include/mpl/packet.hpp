#pragma once
#ifndef MPL_PACKET_HPP
#define MPL_PACKET_HPP

#include "buffer.hpp"
#include <jilog.hpp>

namespace mpl::packet {

    using Type = std::uint32_t;
    using Size = std::uint32_t;

    // hexdump -n 4 -e '"0x" 1 "%08x" "\n"' /dev/urandom 
    static constexpr Type PROBLEM = 0x8179e3f1;
    static constexpr Type HELLO = 0x3864caca;
    static constexpr Type PATH_SE3 = 0xa9db6e7d;
    static constexpr Type PATH_RVF = 0xb11b0c45;
    static constexpr Type PATH_RVD = PATH_RVF + 0x100;
    static constexpr Type DONE = 0x6672e31a;

    static constexpr std::size_t MAX_PACKET_SIZE = 1024*1024;

    static constexpr std::uint32_t ALGORITHM_RRT = 1;
    static constexpr std::uint32_t ALGORITHM_CFOREST = 2;
    
    class protocol_error : public std::runtime_error {
    public:
        protocol_error(const std::string& msg)
            : std::runtime_error(msg)
        {
        }
    };

    class Problem {
    public:
        static constexpr Type TYPE = PROBLEM;

        static std::string name() {
            return "Problem";
        }
        
    private:
        std::uint32_t jobs_;
        std::uint8_t algorithm_;
        std::vector<std::string> args_;

    public:
        // Problem(int argc, char* argv[]) {
        //     args_.reserve(argc-1);
        //     for (int i=1 ; i<argc ; ++i)
        //         args_.push_back(argv[i]);
        // }

        Problem(std::uint32_t jobs, std::uint8_t alg, std::vector<std::string>&& args)
            : jobs_(jobs)
            , algorithm_(alg)
            , args_(std::move(args))
        {
        }

        inline Problem(Type, BufferView buf)
            : jobs_(buf.get<std::uint32_t>())
            , algorithm_(buf.get<std::uint8_t>())
        {
            std::size_t n = buf.get<std::uint8_t>();
            args_.reserve(n);
            for (std::size_t i=0 ; i<n ; ++i)
                args_.push_back(buf.getString(buf.get<std::uint8_t>()));
        }

        inline operator Buffer () const {
            Size size = buffer_size_v<Type> + buffer_size_v<Size> +
                buffer_size_v<std::uint32_t> + buffer_size_v<std::uint8_t> +
                args_.size() + 1;
            for (const std::string& s : args_)
                size += s.size();
            Buffer buf{size};
            buf.put(TYPE);
            buf.put(size);
            buf.put(jobs_);
            buf.put(algorithm_);
            buf.put(static_cast<std::uint8_t>(args_.size()));
            for (const std::string& s : args_) {
                buf.put(static_cast<std::uint8_t>(s.size()));
                buf.put(s);
            }
            buf.flip();
            return buf;
        }

        std::uint32_t jobs() const {
            return jobs_;
        }

        std::uint8_t algorithm() const {
            return algorithm_;
        }

        const std::vector<std::string>& args() const {
            return args_;
        }
    };
    
    class Hello {
        std::uint64_t id_;
        
    public:
        static std::string name() {
            return "Hello";
        }
        
        explicit Hello(std::uint64_t id)
            : id_(id)
        {
        }

        explicit Hello(Type type, BufferView buf)
            : id_(buf.get<std::uint64_t>())
        {
        }

        std::uint64_t id() const {
            return id_;
        }
        
        operator Buffer () const {
            Size size = 16;
            Buffer buf{size};
            buf.put(HELLO);
            buf.put(size);
            buf.put(id_);
            buf.flip();
            return buf;
        }
    };

    class Done {
        std::uint64_t id_;
        
    public:
        static std::string name() {
            return "Done";
        }
        
        explicit Done(std::uint64_t id)
            : id_(id)
        {
        }

        explicit Done(Type type, BufferView buf)
            : id_(buf.get<std::uint64_t>())
        {
        }

        std::uint64_t id() const {
            return id_;
        }
        
        operator Buffer () const {
            Size size = 16;
            Buffer buf{size};
            buf.put(DONE);
            buf.put(size);
            buf.put(id_);
            buf.flip();
            return buf;
        }
    };

    template <class State>
    class PathBase;

    template <class S, int dim>
    class PathBase<Eigen::Matrix<S, dim, 1>> {
    public:
        using Scalar = S;
        static constexpr Type TYPE = (std::is_same_v<S, float> ? PATH_RVF : PATH_RVD) + dim;

        static std::string name() {
            return (std::is_same_v<S, float> ? "Path<RVF" : "Path<RVD")
                + std::to_string(dim) + ">";
        }
    };

    template <class S>
    class PathBase<std::tuple<Eigen::Quaternion<S>, Eigen::Matrix<S, 3, 1>>> {
    public:
        using Scalar = S;
        static constexpr Type TYPE = PATH_SE3 + sizeof(S)/8;

        static std::string name() {
            return (std::is_same_v<S,float> ? "Path<SE3F>" : "Path<SE3D>");
        }
    };


    template <class State>
    class Path : public PathBase<State> {
        using Base = PathBase<State>;
        using Scalar = typename Base::Scalar;
        
    private:
        static constexpr std::size_t stateSize_ = buffer_size_v<State>;

        Scalar cost_;
        std::uint32_t solveTimeMillis_;
        std::vector<State> path_;

    public:
        explicit Path(Scalar cost, std::uint32_t solveTimeMillis, std::vector<State>&& path)
            : cost_(cost)
            , solveTimeMillis_(solveTimeMillis)
            , path_(std::move(path))
        {
        }

        inline Path(Type, BufferView buf)
            : cost_(buf.get<Scalar>())
            , solveTimeMillis_(buf.get<std::uint32_t>())
        {
            if (buf.remaining() % stateSize_ != 0)
                throw protocol_error("invalid path packet size: " + std::to_string(buf.remaining()));
            
            std::size_t n = buf.remaining() / stateSize_;
            path_.reserve(n);
            while (path_.size() < n)
                path_.emplace_back(buf.get<State>());
        }

        inline operator Buffer () const {
            Size size = buffer_size_v<Type> + buffer_size_v<Size>
                + buffer_size_v<Scalar>
                + buffer_size_v<std::uint32_t>
                + stateSize_ * path_.size();
            Buffer buf{size};
            buf.put(Base::TYPE);
            buf.put(size);
            buf.put(cost_);
            buf.put(solveTimeMillis_);
            for (const State& q : path_)
                buf.put(q);
            buf.flip();
            return buf;
        }

        Scalar cost() const {
            return cost_;
        }

        auto solveTimeMillis() const {
            return solveTimeMillis_;
        }

        const std::vector<State>& path() const & {
            return path_;
        }

        std::vector<State>&& path() && {
            return std::move(path_);
        }
    };

    template <class Packet>
    struct is_path : std::false_type {};

    template <class State>
    struct is_path<Path<State>> : std::true_type {};

    template <class Fn>
    std::size_t parse(Buffer& buf, Fn fn) {
        static constexpr auto head = buffer_size_v<Type> + buffer_size_v<Size>;
            
        if (buf.remaining() < head){
            JI_LOG(INFO) << "[parse] early return!" << buf.remaining() ;
            return 8; // head - buf.remaining();
        }

        // bounds checking
        char *start = buf.begin();

        Type type = buf.peek<Type>(0);
        Size size = buf.peek<Size>(buffer_size_v<Type>);

        if (size > MAX_PACKET_SIZE)
            throw protocol_error("maximum packet size exceeded: " + std::to_string(size));

        if (buf.remaining() < size) {
            JI_LOG(TRACE) << "short packet recv, have " << buf.remaining() << ", need " << size;
            return size; // size - buf.remaining();
        }

        buf += head;
        size -= head;
        
        switch (type) {
        case HELLO:
            fn(Hello(type, buf.view(size)));
            break;
        case DONE:
            fn(Done(type, buf.view(size)));
            break;            
        // case PROBLEM_SE3:
        //     fn(ProblemSE3<float>(type, buf.view(size)));
        //     break;
        // case PROBLEM_SE3+1:
        //     fn(ProblemSE3<double>(type, buf.view(size)));
        //     break;
        case PROBLEM:
            fn(Problem(type, buf.view(size)));
            break;
        case PATH_SE3:
            fn(Path<std::tuple<Eigen::Quaternion<float>, Eigen::Matrix<float, 3, 1>>>(type, buf.view(size)));
            break;
        case PATH_SE3+1:
            fn(Path<std::tuple<Eigen::Quaternion<double>, Eigen::Matrix<double, 3, 1>>>(type, buf.view(size)));
            break;
        case PATH_RVF+8:
            fn(Path<Eigen::Matrix<float, 8, 1>>(type, buf.view(size)));
            break;
        case PATH_RVD+8:
            fn(Path<Eigen::Matrix<double, 8, 1>>(type, buf.view(size)));
            break;
        default:
            throw protocol_error("bad packet type: " + std::to_string(type));
        }

        buf += size;
        
        return 0;
    }
}

#endif
