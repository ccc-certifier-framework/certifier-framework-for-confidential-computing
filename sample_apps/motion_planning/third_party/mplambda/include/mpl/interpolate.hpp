#pragma once
#ifndef MPL_INTERPOLATE_HPP
#define MPL_INTERPOLATE_HPP

#include <Eigen/Dense>
#include <tuple>

namespace mpl {
    template <class A, class B>
    typename A::PlainMatrix interpolate(
        const Eigen::MatrixBase<A>& a,
        const Eigen::MatrixBase<B>& b,
        typename A::Scalar t)
    {
        return a + (b - a)*t;
    }

    template <class A, class B>
    Eigen::Quaternion<typename A::Scalar> interpolate(
        const Eigen::QuaternionBase<A>& a,
        const Eigen::QuaternionBase<B>& b,
        typename A::Scalar t)
    {
        return a.slerp(t, b);
    }
    
    template <class A, class B, class S>
    std::tuple<A, B> interpolate(
        const std::tuple<A, B>& from,
        const std::tuple<A, B>& to,
        S t)
    {
        return std::make_tuple(
            interpolate(std::get<0>(from), std::get<0>(to), t),
            interpolate(std::get<1>(from), std::get<1>(to), t));
    }
}

#endif
