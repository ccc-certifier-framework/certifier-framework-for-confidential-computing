#pragma once
#ifndef MPL_DEMO_FETCH_SCENARIO_HPP
#define MPL_DEMO_FETCH_SCENARIO_HPP

#include "fetch_robot.hpp"
#include "load_mesh.hpp"
#include <nigh/lp_space.hpp>

namespace mpl::demo {
    
    template <class S>
    class FetchScenario {
    public:
        using Scalar = S;
        using Robot = FetchRobot<S>;
        using Frame = typename Robot::Frame;
        using Transform = Frame;
        using State = typename Robot::Config;
        using Space = unc::robotics::nigh::L1Space<S, Robot::kDOF>;
        using Distance = S;
        
        static_assert(std::is_same_v<State, typename Space::Type>, "odd that this wouldn't be the case");

    private:
        using Mesh = fcl::BVHModel<fcl::OBBRSS<S>>;

        Space space_;
        
        Mesh environment_;
        Frame envFrame_;

        Frame goal_;
        Eigen::Matrix<S, 6, 1> goalL_;
        S goalEps_;

        S invStepSize_;

        // Scaling applied to the motion planning nearest-neighbors.
        // Since we're computing in L^p space, instead of SO(2), we
        // can apply this scale to make motions involving the torso
        // and shoulder joints more expensive.
        static const State& scale() {
            static State s = (State() << 10, 4, 2, 1, 1, 1, 1, 1).finished();
            return s;
        }

    public:
        FetchScenario(
            const Frame& envFrame,
            const std::string& envMesh,
            const Frame& goal,
            const Eigen::Matrix<S, 6, 1>& goalTol,
            S checkResolution = 0.01)
            : environment_(MeshLoad<Mesh>::load(envMesh, false, true))
            , envFrame_{envFrame}
            , goal_{goal}
            , invStepSize_(1 / checkResolution)
        {
            goalEps_ = goalTol.minCoeff();
            goalL_ = goalEps_ / goalTol.array();

            JI_LOG(INFO) << "goal tolerance: eps=" << goalEps_ << ", L=" << goalL_;
        }

        static constexpr bool multiGoal = true;

        const Space& space() const {
            return space_;
        }

        const Distance maxSteering() const {
            return std::numeric_limits<Distance>::infinity();
        }

        static State scale(const State& q) {
            return q.cwiseProduct(scale());
        }

        template <class RNG>
        State randomSample(RNG& rng) {
            return Robot::randomConfig(rng);
        }

        template <class RNG>
        std::optional<State> sampleGoal(RNG& rng) {
            State near = Robot::randomConfig(rng);
            Robot robot(near);
            if (!robot.ik(goal_, goalL_, goalEps_, 50))
                return {};
            
            // if (isValid(near, robot.config(), false))
            //     JI_LOG(TRACE) << "VALID path to goal";
            
            return robot.config();
        }


        bool isGoal(const State& q) const {
            // HACKY!  using ik solver to see if we're 0 steps away
            // from the goal!
            Robot robot(q);
            return robot.ik(goal_, goalL_, goalEps_, 0);
        }

        bool isValid(const State& q, bool report = false) const {
            Robot robot(q);
            
            if (robot.selfCollision()) {
                if (report)
                    JI_LOG(TRACE) << "self-collision";
                return false;
            }

            if (robot.inCollisionWith(&environment_, envFrame_, report))
                return false;
            
            return true;
        }

        bool isValid(const State& from, const State& to, bool report = false) const {
            assert(isValid(from, report));
            if (!isValid(to, report)) {
                if (report) JI_LOG(TRACE) << " @ t = 1";
                return false;
            }

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
                    if (!isValid(interpolate(from, to, min * delta), report)) {
                        if (report) JI_LOG(TRACE) << " @ t = " << min*delta;
                        return false;
                    }
                } else if (qEnd + 2 < qStart + queue.size()) {
                    std::size_t mid = (min + max) / 2;
                    if (!isValid(interpolate(from, to, mid * delta), report)) {
                        if (report) JI_LOG(TRACE) << " @ t = " << mid*delta;
                        return false;
                    }
                    if (min < mid)
                        queue[qEnd++ % queue.size()] = std::make_pair(min, mid-1);
                    if (mid < max)
                        queue[qEnd++ % queue.size()] = std::make_pair(mid+1, max);
                } else {
                    // queue is full
                    for (std::size_t i=min ; i<=max ; ++i) {
                        if (!isValid(interpolate(from, to, i*delta), report)) {
                            if (report) JI_LOG(TRACE) << " @ t = " << i*delta;
                            return false;
                        }
                    }
                }
            }

            return true;
        }
        
    };
}

#endif
