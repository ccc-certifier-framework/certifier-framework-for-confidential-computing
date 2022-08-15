#pragma once
#ifndef MPL_OPTION_HPP
#define MPL_OPTION_HPP

#include <optional>
#include <string>
#include <stdexcept>
#include <Eigen/Dense>

namespace mpl {
    template <class T>
    struct Option;

    template <>
    struct Option<float> {
        static float parse(const std::string& name, const char *arg, char **endp) {
            float v = std::strtof(arg, endp);
            if (*endp == arg)
                throw std::invalid_argument("bad value for " + name + ": " + arg);
            return v;
        }
    };
    
    template <>
    struct Option<double> {
        static double parse(const std::string& name, const char *arg, char **endp) {
            float v = std::strtod(arg, endp);
            if (*endp == arg)
                throw std::invalid_argument("bad value for " + name + ": " + arg);
            return v;
        }
    };

    template <class S, int dim>
    struct Option<Eigen::Matrix<S, dim, 1>> {
        static Eigen::Matrix<S, dim, 1> parse(const std::string& name, const char *arg, char **endp) {
            Eigen::Matrix<S, dim, 1> q;
            q[0] = Option<S>::parse(name + "[0]", arg, endp);
            for (int i=1 ; i<dim ; ++i) {
                if (**endp != ',')
                    throw std::invalid_argument("expected comma");
                q[i] = Option<S>::parse(name + "[" + std::to_string(i) + "]", *endp + 1, endp);
            }
            return q;
        }
    };

    template <class S>
    struct Option<Eigen::Quaternion<S>> {
        static Eigen::Quaternion<S> parse(const std::string& name, const char *arg, char **endp) {
            auto v = Option<Eigen::Matrix<S, 4, 1>>::parse(name, arg, endp);
            // Eigen::Quaternion<S> q;
            // q = Eigen::AngleAxis<S>{v[0], v.template tail<3>().normalized()};
            // return q;
            return Eigen::Quaternion<S>{v};
        }
    };

    template <class T>
    struct Option<std::optional<T>> {
        static std::optional<T> parse(const std::string& name, const char *arg, char **endp) {
            return Option<T>::parse(name, arg, endp);
        }
    };

    template <class A, class B>
    struct Option<std::tuple<A, B>> {
        static std::tuple<A, B> parse(const std::string& name, const char *arg, char **endp) {
            A a = Option<A>::parse(name, arg, endp);
            if (**endp != ',')
                throw std::invalid_argument("expected comma");
            return { a, Option<B>::parse(name, *endp + 1, endp) };
        }
    };    

    template <class T>
    void parse(const std::string& name, T& value, const char *arg) {
        char *endp;
        value = Option<T>::parse(name, arg, &endp);
        if (*endp != '\0')
            throw std::invalid_argument("extra characters in option");
    }
}

#endif
