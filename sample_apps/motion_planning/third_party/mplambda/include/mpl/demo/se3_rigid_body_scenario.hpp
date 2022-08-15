#pragma once
#ifndef MPL_DEMO_SE3_RIGID_BODY_PLANNING_HPP
#define MPL_DEMO_SE3_RIGID_BODY_PLANNING_HPP

#include <atomic>
#include "load_mesh.hpp"
#include "../interpolate.hpp"
#include "../randomize.hpp"
#include <jilog.hpp>
#include <nigh/se3_space.hpp>
#include <array>

namespace mpl::demo {
    
    template <class S, std::intmax_t so3weight = 50, std::intmax_t l2weight = 1>
    class SE3RigidBodyScenario {
    public:
        using Space = unc::robotics::nigh::SE3Space<S, so3weight, l2weight>;
        using State = typename Space::Type;
        using Bound = Eigen::Matrix<S, 3, 1>;
        using Distance = S;

    private:
        using Mesh = fcl::BVHModel<fcl::OBBRSS<S>>;
        // using Mesh = bump::BVHMesh<bump::Triangle<int>, bump::OBB<S>>;
        // using Transform = Eigen::Transform<S, 3, Eigen::Isometry>;
        using Transform = fcl::Transform3<S>;

        Space space_;
    
        Mesh environment_;
        Mesh robot_;

        State goal_;

        Bound min_;
        Bound max_;

        Distance goalRadius_{0.1};
        Distance invStepSize_;

        mutable std::atomic<unsigned> calls_{0};

        static Transform stateToTransform(const State& q) {
            return Eigen::Translation<S, 3>(std::get<Eigen::Matrix<S, 3, 1>>(q))
                * std::get<Eigen::Quaternion<S>>(q);
        }

    public:
        template <class Min, class Max>
        SE3RigidBodyScenario(
            const std::string& envMesh,
            const std::string& robotMesh,
            const State& goal,
            const Eigen::MatrixBase<Min>& min,
            const Eigen::MatrixBase<Max>& max,
            S checkResolution)
            : environment_(MeshLoad<Mesh>::load(envMesh, false, false))
            , robot_(MeshLoad<Mesh>::load(robotMesh, true, false))
            , goal_(goal)
            , min_(min)
            , max_(max)
            , invStepSize_(1/checkResolution)
        {
            // JI_LOG(INFO) << "loaded env: " << environment_->num_vertices << " vertices, " << environment_->num_tris << " tris";
            // JI_LOG(INFO) << "loaded robot: " << robot_->num_vertices << " vertices, " << robot_->num_tris << " tris";

            // JI_LOG(INFO) << "check resolution = " << 1/invStepSize_;
            
            // auto robotTest = MeshLoad<Mesh>::load(robotMesh, true);
            
            // fcl::CollisionRequest<S> req;
            // fcl::CollisionResult<S> res;
            // Transform id = Transform::Identity();
            // Transform a = Transform::Identity();
            // a *= Eigen::Translation<S,3>(0,0,0.001);
            // JI_LOG(INFO) << a.matrix();
            // JI_LOG(INFO) << "self collision check: " << fcl::collide(robot_, a, robotTest.get(), id, req, res);
            // a *= Eigen::Translation<S,3>(100,1000,100.0);
            // JI_LOG(INFO) << a.matrix();
            // JI_LOG(INFO) << "self collision check: " << fcl::collide(robot_.get(), a, robotTest.get(), id, req, res);
        }

        ~SE3RigidBodyScenario() {
            // JI_LOG(INFO) << "isValid calls: " << calls_.load();
        }

        static constexpr bool multiGoal = true;
        
        static State scale(const State& q) {
            return q;
        }

        const Space& space() const {
            return space_;
        }

        const Distance maxSteering() const {
            return std::numeric_limits<Distance>::infinity();
        }

        template <class RNG>
        std::optional<State> sampleGoal(RNG& rng) {
            return goal_;
        }

        template <class RNG>
        State randomSample(RNG& rng) {
            State q;
            randomize(std::get<Eigen::Quaternion<S>>(q), rng);
            randomize(std::get<Eigen::Matrix<S,3,1>>(q), rng, min_, max_);
            return q;
        }

        bool isGoal(const State& q) const {
            return space_.distance(goal_, q) <= goalRadius_;            
        }

        bool isValid(const State& q) const {
            ++calls_;
            fcl::CollisionRequest<S> req;
            fcl::CollisionResult<S> res;

            Transform tf = stateToTransform(q);
            
            return !fcl::collide(&robot_, tf, &environment_, Transform::Identity(), req, res);
            
            // static Transform id{Transform::Identity()};

            // Transform tf = stateToTransform(q);
            // return !fcl::collide(robot_.get(), tf, environment_.get(), id, req, res);
        }    

        bool isValid(const State& from, const State& to) const {
            assert(isValid(from));
            if (!isValid(to))
                return false;

            std::size_t steps = std::ceil(space_.distance(from, to) * invStepSize_);

            // JI_LOG(DEBUG) << "steps = " << steps;
            
            if (steps < 2)
                return true;

            Distance delta = 1 / Distance(steps);
            // for (std::size_t i = 1 ; i < steps ; ++i)
            //     if (!isValid(interpolate(from, to, i*delta)))
            //         return false;
            
            // if (true) return true;
            
            std::array<std::pair<std::size_t, std::size_t>, 1024> queue;
            queue[0] = std::make_pair(std::size_t(1), steps-1);
            std::size_t qStart = 0, qEnd = 1;
            while (qStart != qEnd) {
                auto [min, max] = queue[qStart++ % queue.size()];
                if (min == max) {
                    if (!isValid(interpolate(from, to, min * delta)))
                        return false;
                } else if (qEnd + 2 < qStart + queue.size()) {
                    std::size_t mid = (min + max) / 2;
                    if (!isValid(interpolate(from, to, mid * delta)))
                        return false;
                    if (min < mid)
                        queue[qEnd++ % queue.size()] = std::make_pair(min, mid-1);
                    if (mid < max)
                        queue[qEnd++ % queue.size()] = std::make_pair(mid+1, max);
                } else {
                    // queue is full
                    for (std::size_t i=min ; i<=max ; ++i)
                        if (!isValid(interpolate(from, to, i*delta)))
                            return false;
                }
            }

            return true;
        }
    };
}

#endif
