#pragma once
#ifndef MPL_DEMO_APP_OPTIONS_HPP
#define MPL_DEMO_APP_OPTIONS_HPP

#include <string>
#include <optional>
#include <Eigen/Dense>
#include "../packet.hpp"
namespace mpl::demo {
    template <class T>
    struct OptionParser;

    template <>
    struct OptionParser<float> {
        static float parse(const std::string& name, const char *arg, char **endp);
    };
    
    template <>
    struct OptionParser<double> {
        static double parse(const std::string& name, const char *arg, char **endp);
    };

    template <class S, int rows>
    struct OptionParser<Eigen::Matrix<S, rows, 1>> {
        static Eigen::Matrix<S, rows, 1> parse(const std::string& name, const char *arg, char **endp) {
            if (!*arg)
                throw std::invalid_argument(name + " is required");
            
            Eigen::Matrix<S, rows, 1> q;
            q[0] = OptionParser<S>::parse(name, arg, endp);
            for (int i=1 ; i<rows ; ++i) {
                if (**endp != ',')
                    throw std::invalid_argument("expected comma");
                q[i] = OptionParser<S>::parse(name, *endp + 1, endp);
            }
            return q;
        }
    };

    template <class S>
    struct OptionParser<Eigen::Quaternion<S>> {
        static Eigen::Quaternion<S> parse(const std::string& name, const char *arg, char **endp) {
            auto v = OptionParser<Eigen::Matrix<S, 4, 1>>::parse(name, arg, endp);
            // Eigen::Quaternion<S> q;
            // q = Eigen::AngleAxis<S>{v[0], v.template tail<3>().normalized()};
            // return q;
            return Eigen::Quaternion<S>{v};
        }
    };

    template <class A, class B>
    struct OptionParser<std::tuple<A, B>> {
        static std::tuple<A, B> parse(const std::string& name, const char *arg, char **endp) {
            A a = OptionParser<A>::parse(name, arg, endp);
            if (**endp != ',')
                throw std::invalid_argument("expected comma");
            return { a, OptionParser<B>::parse(name, *endp + 1, endp) };
        }
    };

    template <class S, int mode>
    struct OptionParser<Eigen::Transform<S, 3, mode>> {
        using Result = Eigen::Transform<S, 3, mode>;
        static Result parse(const std::string& name, const char *arg, char **endp) {
            if (!*arg)
                throw std::invalid_argument("expected comma");
            std::vector<S> q;
            q.push_back(OptionParser<S>::parse(name, arg, endp));
            while (*(arg = *endp) != '\0') {
                if (*arg != ',')
                    throw std::invalid_argument("expected comma");
                q.push_back(OptionParser<S>::parse(name, arg+1, endp));
            }

            if (q.size() == 3) {
                Result t;
                t.setIdentity();
                Eigen::AngleAxis<S> aa(q[2], Eigen::Matrix<S, 3, 1>::UnitZ());
                t.linear() = aa.toRotationMatrix();
                t.translation() << q[0], q[1], 0;
                return t;
            } else if (q.size() == 6) {
                Eigen::Matrix<S, 3, 1> axis;
                Result t;
                t.setIdentity();
                axis << q[3], q[4], q[5];
                S angle = axis.norm();
                if (std::abs(angle) > 1e-6) {
                    Eigen::AngleAxis<S> aa(angle, axis / angle);
                    t.linear() = aa.toRotationMatrix();
                }
                t.translation() << q[0], q[1], q[2];
                return t;
            } else {
                throw std::invalid_argument(name + " only supports 3 or 6 arguments");
            }
        }
    };

    template <class T>
    struct OptionParser<std::optional<T>> {
        static std::optional<T> parse(const std::string& name, const char *arg, char **endp) {
            if (*arg)
                return OptionParser<T>::parse(name, arg, endp);
            else
                return {};
        }
    };
    
    class AppOptions {
    public:
        static constexpr unsigned long MAX_JOBS = 1000;
        unsigned long int timeStart; 
        
        std::string scenario_ ;
        std::string algorithm_ ;
        std::string coordinator_;
        unsigned long jobs_{4};
        
        std::uint64_t problemId_;

        std::string env_; 
        std::string robot_;
        std::string envFrame_;

        std::string start_ ;
        std::string goal_ ;
        std::string goalRadius_;

        std::string min_ ;
        std::string max_ ;
	std::uint16_t thread_id_ = 0;

        double timeLimit_{std::numeric_limits<double>::infinity()};
        double checkResolution_{0};

        bool singlePrecision_{false};

    private:
        static void usage(const char *argv0);

        template <class T>
        static T parse(const std::string& name, const std::string& value) {
            char *endp;
            T r = OptionParser<T>::parse(name, value.c_str(), &endp);
            if (*endp)
                throw std::invalid_argument("extra characters in --" + name);
            return r;
        }
        
    public:
        inline AppOptions() {}
        
        packet::Problem toProblemPacket() const;

        const std::string& scenario(bool required = true) const {
            if (required && scenario_.empty())
                throw std::invalid_argument("--scenario is required");
            return scenario_;
        }
        
        const std::string& algorithm(bool required = true) const {
            if (required && algorithm_.empty())
                throw std::invalid_argument("--algorithm is required");
            return algorithm_;
        }
        
        const std::string& coordinator(bool required = true) const {
            if (required && coordinator_.empty())
                throw std::invalid_argument("--coordinator is required");
            return coordinator_;
        }
        
        const std::uint64_t problemId() const {
            return problemId_;
        }
        
        const std::string& env(bool required = true) const {
            if (required && env_.empty())
                throw std::invalid_argument("--env is required");
            return env_;
        }

        template <class T>
        T envFrame() const {
            return parse<T>("env-frame", envFrame_);
        }
        
        const std::string& robot(bool required = true) const {
            if (required && robot_.empty())
                throw std::invalid_argument("--robot is required");
            return robot_;
        }

        bool singlePrecision() const {
            return singlePrecision_;
        }


        template <class T>
        T start() const {
            return parse<T>("start", start_);
        }

        template <class T>
        T goal() const {
            return parse<T>("goal", goal_);
        }

        template <class T>
        T goalRadius() const {
            return parse<T>("goal-radius", goalRadius_);
        }
        
        template <class T>
        T min() const {
            return parse<T>("min", min_);
        }

        template <class T>
        T max() const {
            return parse<T>("max", max_);
        }

        double timeLimit() const {
            return timeLimit_;
        }

        double checkResolution(double defaultIfZero) const {
            return checkResolution_ <= 0 ? defaultIfZero : checkResolution_;
        }
    };
}

#endif
