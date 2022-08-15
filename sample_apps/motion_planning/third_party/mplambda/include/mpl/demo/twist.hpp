#pragma once
#ifndef MPL_DEMO_TWIST_HPP
#define MPL_DEMO_TWIST_HPP

#include <Eigen/Dense>

namespace mpl::demo {
    template <class S>
    class Twist {
        using Scalar = S;
        
        Eigen::Matrix<Scalar, 6, 1> m_;

    public:
        Twist() {
        }
        
        template <typename V, typename R>
        Twist(const Eigen::MatrixBase<V>& v, const Eigen::MatrixBase<R>& r) {
            m_.template head<3>() = v;
            m_.template tail<3>() = r;
        }

        template <typename R>
        static Twist rotation(const Eigen::MatrixBase<R>& axis) {
            return Twist(Eigen::Matrix<Scalar, 3, 1>::Zero(), axis);
        }

        template <typename T>
        static Twist translation(const Eigen::MatrixBase<T>& dir) {
            return Twist(dir, Eigen::Matrix<Scalar, 3, 1>::Zero());
        }

        decltype(auto) velocity() {
            return m_.template head<3>();
        }

        decltype(auto) velocity() const {
            return m_.template head<3>();
        }

        decltype(auto) rotation() {
            return m_.template tail<3>();
        }

        decltype(auto) rotation() const {
            return m_.template tail<3>();
        }

        void setZero() {
            m_.setZero();
        }

        const auto& matrix() const {
            return m_;
        }

        template <class V>
        Twist refPoint(const Eigen::MatrixBase<V>& vBaseAB) {
            return Twist(
                velocity() + rotation().cross(vBaseAB),
                rotation());
        }

        static Twist diff(
            const Eigen::Transform<Scalar, 3, Eigen::AffineCompact>& a,
            const Eigen::Transform<Scalar, 3, Eigen::AffineCompact>& b)
        {
            Eigen::AngleAxis<Scalar> aa(a.linear().transpose() * b.linear());
            return Twist(
                b.translation() - a.translation(),
                a.linear() * (aa.axis() * aa.angle()));
        }                          
    };

    template <class M, class S>
    Twist<S> operator * (const Eigen::MatrixBase<M>& m, const Twist<S>& tw) {
        return { m * tw.velocity(), m * tw.rotation() };
    }
}

#endif
