#pragma once
#ifndef MPL_RANDOMIZE_HPP
#define MPL_RANDOMIZE_HPP

#include <random>
#include <Eigen/Dense>

namespace mpl {
    template <class S, class RNG>
    void randomize(Eigen::Quaternion<S>& q, RNG& rng) {
        static constexpr S PI = 3.1415926535897932384626433832795028841968L;
        static std::uniform_real_distribution<S> dist01(0, 1);
        static std::uniform_real_distribution<S> dist2pi(0, 2*PI);
        
        S a = dist01(rng);
        S b = dist2pi(rng);
        S c = dist2pi(rng);
        
        q.coeffs()[0] = std::sqrt(1-a)*std::sin(b);
        q.coeffs()[1] = std::sqrt(1-a)*std::cos(b);
        q.coeffs()[2] = std::sqrt(a)*std::sin(c);
        q.coeffs()[3] = std::sqrt(a)*std::cos(c);
    }

    template <class S, int dim, class RNG>
    void randomize(
        Eigen::Matrix<S, dim, 1>& q, RNG& rng,
        const Eigen::Matrix<S, dim, 1>& min,
        const Eigen::Matrix<S, dim, 1>& max)
    {
        for (int i=0 ; i<dim ; ++i) {
            std::uniform_real_distribution<S> dist(min[i], max[i]);
            q[i] = dist(rng);
        }
    }
}

#endif
