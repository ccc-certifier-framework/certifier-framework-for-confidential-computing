#pragma once
#ifndef MPL_FEMO_FETCH_ROBOT_HPP
#define MPL_FEMO_FETCH_ROBOT_HPP

#include "twist.hpp"
#include "blender_py.hpp"
#include "../../jilog.hpp"
#include <Eigen/Dense>
#include <random>
#include <fcl/narrowphase/collision.h>

namespace mpl::demo {

    template <class S>
    class Origin {
        using Scalar = S;
        using Transform = fcl::Transform3<S>; // Eigen::Transform<Scalar, 3, Eigen::AffineCompact>;
        using Vec3 = Eigen::Matrix<Scalar, 3, 1>;
        
        Transform m_;

    public:
        Origin(Scalar tx, Scalar ty, Scalar tz, Scalar roll, Scalar pitch, Scalar yaw) {
            using R = Eigen::AngleAxis<Scalar>;
            
            m_.linear() =
                (R(yaw, Vec3::UnitZ()) * R(pitch, Vec3::UnitY()) * R(roll, Vec3::UnitX()))
                .toRotationMatrix();
            m_.translation() = Vec3{tx, ty, tz};
        }

        operator const Transform& () const {
            return m_;
        }
    };

    template <class S>
    struct FetchCollisionGeometry {
        using Scalar = S;
        
        fcl::Cylinder<S> base_{0.29, 0.32 - 0.02};
        fcl::Box<S> torsoLift_{0.18 + 0.08, 0.34, 1.5};
        fcl::Capsule<S> shoulderPan_{0.0525, 0.29};
        fcl::Cylinder<S> shoulderLift_{0.06, 0.145};
        fcl::Capsule<S> upperarmRoll_{0.0525, 0.24};
        fcl::Cylinder<S> elbowFlex_{0.0525, 0.14};
        fcl::Capsule<S> forearmRoll_{0.0525, 0.215};
        fcl::Cylinder<S> wristFlex_{0.0525, 0.155};
        fcl::Capsule<S> wristRoll_{0.0525, 0.09};
        fcl::Box<S> gripper_{0.12 + 0.0625 * 2, 0.125, 0.075};
        fcl::Capsule<S> neck_{0.085 * 1.1, 0.04 * 1.1};
        fcl::Cylinder<S> head_{0.24 * 1.05, 0.115 * 1.05};
    };

    template <class S>
    struct BPYLink {
        std::string parent_;
        std::string name_;
        Eigen::Matrix<S, 3, 1> location_;

        BPYLink(const std::string& parent, const std::string& name, S x, S y, S z)
            : parent_(parent), name_(name), location_(x, y, z)
        {
        }

        template <class Char, class Traits>
        friend decltype(auto) operator << (std::basic_ostream<Char, Traits>& out, const BPYLink& link) {
            return out << link.name_;
        }
    };
    
    template <class S>
    class FetchRobot {
    public:
        using Scalar = S;
        using Transform = fcl::Transform3<S>;
        using Frame = Transform;
        using Vec3 = Eigen::Matrix<Scalar, 3, 1>;

        enum {
            kTorsoLiftJoint,
            
            kShoulderPanJoint,
            kShoulderLiftJoint,
            kUpperarmRollJoint,
            kElbowFlexJoint,
            kForearmRollJoint,
            kWristFlexJoint,
            kWristRollJoint,

            kDOF
        };

        static constexpr S PI = 3.14159265358979323846264338327950288419716939937510582097494459230781640628620L;

        // keep the gripper from hitting the floor
        static constexpr S floorClearance_ = 0.30;
        
        using Config = Eigen::Matrix<S, kDOF, 1>;
        using Jacobian = Eigen::Matrix<S, 6, kDOF>;

        // Collision geometry does not change from one robot to the
        // next, so we keep around a static copy of it.
        static const auto& collisionGeometry() {
            static FetchCollisionGeometry<S> collisionGeometry_;
            return collisionGeometry_;
        }

        static Config jointMin() {
            Config q;
            q[kTorsoLiftJoint] = 0.0;
            q[kShoulderPanJoint] = -1.6056;
            q[kShoulderLiftJoint] = -1.221;
            q[kUpperarmRollJoint] = -std::numeric_limits<Scalar>::infinity();
            q[kElbowFlexJoint] = -2.251;
            q[kForearmRollJoint] = -std::numeric_limits<Scalar>::infinity();
            q[kWristFlexJoint] = -2.16;
            q[kWristRollJoint] = -std::numeric_limits<Scalar>::infinity();
            return q;
        }

        static Config jointMax() {
            Config q;
            q[kTorsoLiftJoint] = 0.38615;
            q[kShoulderPanJoint] = 1.6056;
            q[kShoulderLiftJoint] = 1.518;
            q[kUpperarmRollJoint] = std::numeric_limits<Scalar>::infinity();
            q[kElbowFlexJoint] = 2.251;
            q[kForearmRollJoint] = std::numeric_limits<Scalar>::infinity();
            q[kWristFlexJoint] = 2.16;
            q[kWristRollJoint] = std::numeric_limits<Scalar>::infinity();
            return q;
        }

        static Config vMax() {
            Config q;
            q[kTorsoLiftJoint] = 0.1;
            q[kShoulderPanJoint] = 1.256;
            q[kShoulderLiftJoint] = 1.454;
            q[kUpperarmRollJoint] = 1.571;
            q[kElbowFlexJoint] = 1.521;
            q[kForearmRollJoint] = 1.571;
            q[kWristFlexJoint] = 2.268;
            q[kWristRollJoint] = 2.268;
            return q;
        }

        static Config eMax() {
            Config q;
            q[kTorsoLiftJoint] = 450.0;
            q[kShoulderPanJoint] = 33.82;
            q[kShoulderLiftJoint] = 131.76;
            q[kUpperarmRollJoint] = 76.94;
            q[kElbowFlexJoint] = 66.18;
            q[kForearmRollJoint] = 29.35;
            q[kWristFlexJoint] = 25.7;
            q[kWristRollJoint] = 7.36;
            return q;
        }

    public:
        template <class RNG>
        static Config randomConfig(RNG& rng) {
            // sample unbounded joints in the range -PI to +PI.  Note:
            // torso_lift is included in this cwise min/max, but to no
            // effect since its bounds are less than +/- 3.14 meters.
            static Config min = jointMin().cwiseMax(-4*PI);
            static Config max = jointMax().cwiseMin(+4*PI);
            Config q;
            for (int i=0 ; i < kDOF ; ++i) {
                std::uniform_real_distribution<S> dist(min[i], max[i]);
                q[i] = dist(rng);
            }
            return q;
        }

        static const Config& restConfig() {
            static const S deg90 = 3.14159265358979323846264338327950288419716939937510582097494459230781640628620L /2;
            static Config q =
                (Config() <<
                 0.1,
                 deg90, // shoulder pan
                 deg90, // shoulder lift
                 0,  // upperarm roll
                 deg90, // elbow flex
                 0,  // forearm roll
                 deg90, // wrist flex
                 0   // wrist roll
                ).finished();
            return q;
        }

    private:
        Config config_;

        Frame baseLink_{Frame::Identity()};
        
        Frame torsoLiftJointOrigin_;
        Frame torsoLiftLink_;
        Frame shoulderPanJointOrigin_;
        Frame shoulderPanLink_;
        Frame shoulderLiftJointOrigin_;
        Frame shoulderLiftLink_;
        Frame upperarmRollJointOrigin_;
        Frame upperarmRollLink_;
        Frame elbowFlexJointOrigin_;
        Frame elbowFlexLink_;
        Frame forearmRollJointOrigin_;
        Frame forearmRollLink_;
        Frame wristFlexJointOrigin_;
        Frame wristFlexLink_;
        Frame wristRollJointOrigin_;
        Frame wristRollLink_;
        Frame gripperAxis_;
        Frame gripperLink_;

        Frame tfBaseLink() const {
            const static Origin<Scalar> originBaseLink{0, 0, 0.1975, 0, 0, 0};
            return baseLink_ * originBaseLink;
        }

        Frame tfTorsoLiftLink() const {
            const static Origin<Scalar> originTorsoLiftLink{-0.09, 0, 0.31, 0, 0, 0};
            return torsoLiftLink_ * originTorsoLiftLink;
        }

        Frame tfShoulderPanLink() const {
            const static Origin<Scalar> originShoulderPanLink{0, 0, -0.025, 0, 0, 0};
            return shoulderPanLink_ * originShoulderPanLink;
        }

        Frame tfShoulderLiftLink() const {
            const static Origin<Scalar> originShoulderLiftLink{0, -0.0025, 0, 1.5708, 0, 0};
            return shoulderLiftLink_ * originShoulderLiftLink;
        }

        Frame tfUpperarmRollLink() const {
            const static Origin<Scalar> originUpperarmRollLink{-0.04, 0, 0, 0, 1.5708, 0};
            return upperarmRollLink_ * originUpperarmRollLink;
        }

        Frame tfElbowFlexLink() const {
            const static Origin<Scalar> originElbowFlexLink{0, 0, 0, 1.5708, 0, 0};
            return elbowFlexLink_ * originElbowFlexLink;
        }
        
        Frame tfForearmRollLink() const {
            const static Origin<Scalar> originForearmRollLink{-0.04, 0, 0, 0, 1.5708, 0};
            return forearmRollLink_ * originForearmRollLink;
        }

        Frame tfWristFlexLink() const {
            const static Origin<Scalar> originWristFlexLink{0, -0.01, 0, 1.5708, 0, 0};
            return wristFlexLink_ * originWristFlexLink;
        }

        Frame tfWristRollLink() const {
            const static Origin<Scalar> originWristRollLink{-0.045, 0, 0, 0, 1.5708, 0};
            return wristRollLink_ * originWristRollLink;
        }

        const Frame& tfGripperLink() const {
            return gripperLink_;
        }

        Frame tfNeckLink() const {
            const static Origin<Scalar> originNeckLink{0.053125, 0, 0.603001417713939, 0, 0, 0};
            return torsoLiftLink_ * originNeckLink;
        }

        Frame tfHeadLink() const {
            const static Origin<Scalar> originHeadLink{0.053125, 0, 0.603001417713939 + 0.115/2, 0, 0, 0};
            return torsoLiftLink_ * originHeadLink;
        }
        
        void fk() {
            using T = Eigen::Translation<Scalar, 3>;
            using R = Eigen::AngleAxis<Scalar>;
            
            torsoLiftJointOrigin_ = baseLink_ * T(-0.086875, 0, 0.37743);
            torsoLiftLink_ = torsoLiftJointOrigin_ * T(0, 0, config_[kTorsoLiftJoint]);

            shoulderPanJointOrigin_ = torsoLiftLink_ * T(0.119525, 0, 0.34858);
            shoulderPanLink_ = shoulderPanJointOrigin_ * R(config_[kShoulderPanJoint], Vec3::UnitZ());
            
            shoulderLiftJointOrigin_ = shoulderPanLink_ * T(0.117, 0, 0.0599999999999999);
            shoulderLiftLink_ = shoulderLiftJointOrigin_ * R(config_[kShoulderLiftJoint], Vec3::UnitY());
            
            upperarmRollJointOrigin_ = shoulderLiftLink_ * T(0.219, 0, 0);
            upperarmRollLink_ = upperarmRollJointOrigin_ * R(config_[kUpperarmRollJoint], Vec3::UnitX());

            elbowFlexJointOrigin_ = upperarmRollLink_ * T(0.133, 0, 0);
            elbowFlexLink_ = elbowFlexJointOrigin_ * R(config_[kElbowFlexJoint], Vec3::UnitY());
            
            forearmRollJointOrigin_ = elbowFlexLink_ * T(0.197, 0, 0);
            forearmRollLink_ = forearmRollJointOrigin_ * R(config_[kForearmRollJoint], Vec3::UnitX());
            
            wristFlexJointOrigin_ = forearmRollLink_ * T(0.1245, 0, 0);
            wristFlexLink_ = wristFlexJointOrigin_ * R(config_[kWristFlexJoint], Vec3::UnitY());
            
            wristRollJointOrigin_ = wristFlexLink_ * T(0.1385, 0, 0);
            wristRollLink_ = wristRollJointOrigin_ * R(config_[kWristRollJoint], Vec3::UnitX());

            gripperAxis_ = wristRollLink_ * T(0.16645, 0, 0);
            gripperLink_ = gripperAxis_ * T(-0.09, 0, 0.0025);

            // headPanJointOrigin_ = torsoLiftLink_ * T(0.053125, 0, 0.603001417713939);
            // headPanLink_ = headPanJointOrigin_ * R(config_[kHeadPanJoint], Vec3::UnitZ());

            // headTiltJointOrigin_ = headPanLink_ * T(0.14253, 0, 0.057999);
            // headTiltLink_ = headTiltJointOrigin_ * R(config_[kHeadTiltJoint], Vec3::UnitY());

            // rGripperFingerJointOrigin_ = gripperAxis_ * T(0, 0.015425, 0);
            // lGripperFingerJointOrigin_ = gripperAxis_ * T(0,-0.015425, 0);
        }

    public:
        FetchRobot() {
        }

        FetchRobot(const Config& q) {
            setConfig(q);
        }

        const Config& config() const {
            return config_;
        }

        void setConfig(const Config& q) {
            config_ = q;
            fk();
        }

        const Frame& baseLink() const { return baseLink_; }
        const Frame& torsoLiftJointOrigin() const { return torsoLiftJointOrigin_; }
        const Frame& torsoLiftLink() const { return torsoLiftLink_; }
        // const Frame& headPanJointOrigin() const { return headPanJointOrigin_; }
        // const Frame& headPanLink() const { return headPanLink_; }
        // const Frame& headTiltJointOrigin() const { return headTiltJointOrigin_; }
        // const Frame& headTiltLink() const { return headTiltLink_; }
        const Frame& shoulderPanJointOrigin() const { return shoulderPanJointOrigin_; }
        const Frame& shoulderPanLink() const { return shoulderPanLink_; }
        const Frame& shoulderLiftJointOrigin() const { return shoulderLiftJointOrigin_; }
        const Frame& shoulderLiftLink() const { return shoulderLiftLink_; }
        const Frame& upperarmRollJointOrigin() const { return upperarmRollJointOrigin_; }
        const Frame& upperarmRollLink() const { return upperarmRollLink_; }
        const Frame& elbowFlexJointOrigin() const { return elbowFlexJointOrigin_; }
        const Frame& elbowFlexLink() const { return elbowFlexLink_; }
        const Frame& forearmRollJointOrigin() const { return forearmRollJointOrigin_; }
        const Frame& forearmRollLink() const { return forearmRollLink_; }
        const Frame& wristFlexJointOrigin() const { return wristFlexJointOrigin_; }
        const Frame& wristFlexLink() const { return wristFlexLink_; }
        const Frame& wristRollJointOrigin() const { return wristRollJointOrigin_; }
        const Frame& wristRollLink() const { return wristRollLink_; }
        const Frame& gripperAxis() const { return gripperAxis_; }

        // TODO: the gripperLink_ frame is actually in the center of
        // the box that holds the gripper jaws.  The EE frame should
        // be between the grippers.
        const Frame& getEndEffectorFrame() const {
            return gripperLink_;
        }

        Jacobian jacobian() const {
            using Twist = mpl::demo::Twist<S>;

            // it might make sense to make `end` be a parameter or
            // modified by a parameter.
            const Frame& end = getEndEffectorFrame();
            
            Jacobian J;
            
            J.col(kTorsoLiftJoint) = (torsoLiftJointOrigin_.linear() * Twist::translation(Vec3::UnitZ()))
                .refPoint(end.translation() - torsoLiftLink_.translation()).matrix();
                
            J.col(kShoulderPanJoint) = (shoulderPanJointOrigin_.linear() * Twist::rotation(Vec3::UnitZ()))
                .refPoint(end.translation() - shoulderPanLink_.translation()).matrix();
                
            J.col(kShoulderLiftJoint) = (shoulderLiftJointOrigin_.linear() * Twist::rotation(Vec3::UnitY()))
                .refPoint(end.translation() - shoulderLiftLink_.translation()).matrix();
            
            J.col(kUpperarmRollJoint) = (upperarmRollJointOrigin_.linear() * Twist::rotation(Vec3::UnitX()))
                .refPoint(end.translation() - upperarmRollLink_.translation()).matrix();
                
            J.col(kElbowFlexJoint) = (elbowFlexJointOrigin_.linear() * Twist::rotation(Vec3::UnitY()))
                .refPoint(end.translation() - elbowFlexLink_.translation()).matrix();
            
            J.col(kForearmRollJoint) = (forearmRollJointOrigin_.linear() * Twist::rotation(Vec3::UnitX()))
                .refPoint(end.translation() - forearmRollLink_.translation()).matrix();
            
            J.col(kWristFlexJoint) = (wristFlexJointOrigin_.linear() * Twist::rotation(Vec3::UnitY()))
                .refPoint(end.translation() - wristFlexLink_.translation()).matrix();
            
            J.col(kWristRollJoint) = (wristRollJointOrigin_.linear() * Twist::rotation(Vec3::UnitX()))
                .refPoint(end.translation() - wristRollLink_.translation()).matrix();
            
            return J;
        }

        // Compute an IK solution using LMA based upon the current
        // configuration.  This method returns true if successful,
        // false if not.  This method modifies the current
        // configuration of the robot regardless of success or
        // failure.  If successful, the IK solution can be obtained
        // from the `config()` method, and the robot's joint frames
        // will be set to their FK solution.  If unsuccessful, the
        // `config()` of the robot will be the closest configuration
        // that the LMA solver could find.  It may or may not be a
        // useful configuration.
        bool ik(
            const Frame& target,
            const Eigen::Matrix<S, 6, 1>& L,
            S eps = 1e-3,
            unsigned maxIters = 500,
            S epsJoints = std::numeric_limits<S>::epsilon()*4)
        {
            static constexpr bool debug = false;
            
            using Twist = mpl::demo::Twist<S>;
            using Delta = Eigen::Matrix<S, 6, 1>;
            const S epsSqr = eps*eps;
            Config q = config_;

            Delta deltaPos = L.asDiagonal() * Twist::diff(getEndEffectorFrame(), target).matrix();
            S deltaPosNormSquared = deltaPos.squaredNorm();
            if (deltaPosNormSquared < epsSqr) {
                if (debug) std::clog << "already in a solution configuration" << std::endl;
                return true;
            }

            if (maxIters == 0) {
                if (debug) std::clog << "maxIters = 0" << std::endl;
                return false;
            }

            Jacobian J = L.asDiagonal() * jacobian();
            S v = 2;
            S lambda = 10;

            for (unsigned iter = 1 ; iter <= maxIters ; ++iter) {
                Config grad = J.transpose() * deltaPos;
                Eigen::Matrix<S, kDOF, kDOF> jTj = (J.transpose() * J).eval();
                jTj.diagonal() *= 1 + 1/lambda;
                Config diffq = jTj.colPivHouseholderQr().solve(grad);
                S dNorm = diffq.cwiseAbs().maxCoeff();

                if (dNorm < epsJoints) {
                    if (debug) std::clog << "failed: joint increment is too small" << std::endl;
                    return false;
                }

                if (grad.transpose() * grad < epsJoints*epsJoints) {
                    if (debug) std::clog << "failed: joint gradient is too small" << std::endl;
                    return false;
                }

                // TODO: jointMin and jointMax are recomputed every
                // time (unless the compiler is smart enough to cache
                // it).  These should be cached in static variables
                // somewhere
                setConfig(
                    (q + diffq)
                    .cwiseMax(jointMin())
                    .cwiseMin(jointMax()));

                Delta deltaPosNew = L.asDiagonal() * Twist::diff(getEndEffectorFrame(), target).matrix();
                S deltaPosNewNormSquared = deltaPosNew.squaredNorm();

                S rho = (deltaPosNormSquared - deltaPosNewNormSquared)
                    / (diffq.transpose() * (lambda * diffq + grad));

                if (debug) std::clog << "d=" << deltaPosNewNormSquared << ", rho=" << rho << ", lambda=" << lambda << ", q=" << config_.transpose() << std::endl;
                // std::clog << "rho = " << rho << ", lambda=" << lambda << ", dPos: " << deltaPosNormSquared << " -> " << deltaPosNewNormSquared << std::endl;

                if (rho <= 0) {
                    lambda *= v;
                    v *= 2;
                    if (lambda == std::numeric_limits<Scalar>::infinity()) {
                        if (debug) std::clog << "failed: lambda overflow" << std::endl;
                        return false;
                    }
                } else {
                    q = config_;
                    deltaPos = deltaPosNew;
                    deltaPosNormSquared = deltaPosNewNormSquared;
                    if (deltaPosNewNormSquared < epsSqr) {
                        if (debug) std::clog << "SOLVED!" << std::endl;
                        return true; // solved!
                    }

                    J = L.asDiagonal() * jacobian();
                    S x = 2*rho - 1;
                    lambda *= std::max(1/S(3), 1 - x*x*x);
                    v = 2;
                }                     
            }

            if (debug) std::clog << "failed: too many iterations" << std::endl;
            return false;
        }

        bool selfCollision() const {
            fcl::CollisionRequest<S> req;
            fcl::CollisionResult<S> res;

            const auto& G = collisionGeometry();

            if (fcl::collide(&G.base_, tfBaseLink(), &G.forearmRoll_, tfForearmRollLink(), req, res))
                return true;

            if (fcl::collide(&G.base_, tfBaseLink(), &G.wristFlex_, tfWristFlexLink(), req, res))
                return true;

            if (fcl::collide(&G.base_, tfBaseLink(), &G.wristRoll_, tfWristRollLink(), req, res))
                return true;

            if (fcl::collide(&G.base_, tfBaseLink(), &G.gripper_, tfGripperLink(), req, res))
                return true;

            if (fcl::collide(&G.torsoLift_, tfTorsoLiftLink(), &G.forearmRoll_, tfForearmRollLink(), req, res))
                return true;
            
            if (fcl::collide(&G.torsoLift_, tfTorsoLiftLink(), &G.wristFlex_, tfWristFlexLink(), req, res))
                return true;
            
            if (fcl::collide(&G.torsoLift_, tfTorsoLiftLink(), &G.wristRoll_, tfWristRollLink(), req, res))
                return true;
            
            if (fcl::collide(&G.torsoLift_, tfTorsoLiftLink(), &G.gripper_, tfGripperLink(), req, res))
                return true;
            
            if (fcl::collide(&G.shoulderPan_, tfShoulderPanLink(), &G.forearmRoll_, tfForearmRollLink(), req, res))
                return true;
            
            if (fcl::collide(&G.shoulderPan_, tfShoulderPanLink(), &G.wristFlex_, tfWristFlexLink(), req, res))
                return true;
            
            if (fcl::collide(&G.shoulderPan_, tfShoulderPanLink(), &G.wristRoll_, tfWristRollLink(), req, res))
                return true;
            
            if (fcl::collide(&G.shoulderPan_, tfShoulderPanLink(), &G.gripper_, tfGripperLink(), req, res))
                return true;
            
            if (fcl::collide(&G.shoulderLift_, tfShoulderLiftLink(), &G.wristRoll_, tfWristRollLink(), req, res))
                return true;
            
            if (fcl::collide(&G.upperarmRoll_, tfUpperarmRollLink(), &G.wristRoll_, tfWristRollLink(), req, res))
                return true;
            
            if (fcl::collide(&G.upperarmRoll_, tfUpperarmRollLink(), &G.gripper_, tfGripperLink(), req, res))
                return true;
            
            if (fcl::collide(&G.upperarmRoll_, tfUpperarmRollLink(), &G.head_, tfHeadLink(), req, res))
                return true;
            
            if (fcl::collide(&G.elbowFlex_, tfElbowFlexLink(), &G.head_, tfHeadLink(), req, res))
                return true;
            
            if (fcl::collide(&G.forearmRoll_, tfForearmRollLink(), &G.head_, tfHeadLink(), req, res))
                return true;
            
            if (fcl::collide(&G.wristFlex_, tfWristFlexLink(), &G.neck_, tfNeckLink(), req, res))
                return true;
            
            if (fcl::collide(&G.wristFlex_, tfWristFlexLink(), &G.head_, tfHeadLink(), req, res))
                return true;
            
            if (fcl::collide(&G.wristRoll_, tfWristRollLink(), &G.neck_, tfNeckLink(), req, res))
                return true;
            
            if (fcl::collide(&G.wristRoll_, tfWristRollLink(), &G.head_, tfHeadLink(), req, res))
                return true;
            
            if (fcl::collide(&G.gripper_, tfGripperLink(), &G.neck_, tfNeckLink(), req, res))
                return true;
            
            if (fcl::collide(&G.gripper_, tfGripperLink(), &G.head_, tfHeadLink(), req, res))
                return true;

            if (gripperAxis_.translation()[2] < floorClearance_)
                return true;
            
            return false;
        }

        bool cc(
            const fcl::CollisionGeometry<S>* ag,
            const Frame& af,
            const char *aName,
            const fcl::CollisionGeometry<S>* bg,
            const Frame& bf,
            const char *bName,
            fcl::CollisionRequest<S>& req,
            fcl::CollisionResult<S>& res,
            bool report) const
        {
            if (!fcl::collide(ag, af, bg, bf, req, res))
                return false;
            if (report)
                JI_LOG(TRACE) << "collision: " << aName << " <-> " << bName;
            return true;
        }
   
        bool inCollisionWith(const fcl::CollisionGeometry<S>* geom, const Frame& frame, bool report = false) const {
            fcl::CollisionRequest<S> req;
            fcl::CollisionResult<S> res;

            const auto& G = collisionGeometry();

            if (cc(geom, frame, "geom", &G.base_, tfBaseLink(), "base", req, res, report))
                return true;

            if (cc(geom, frame, "geom", &G.torsoLift_, tfTorsoLiftLink(), "torsoLift", req, res, report))
                return true;

            if (cc(geom, frame, "geom", &G.shoulderPan_, tfShoulderPanLink(), "shoulderPan", req, res, report))
                return true;

            if (cc(geom, frame, "geom", &G.shoulderLift_, tfShoulderLiftLink(), "shoulderLift", req, res, report))
                return true;

            if (cc(geom, frame, "geom", &G.upperarmRoll_, tfUpperarmRollLink(), "upperarmRoll", req, res, report))
                return true;
            
            if (cc(geom, frame, "geom", &G.elbowFlex_, tfElbowFlexLink(), "elbowFlex", req, res, report))
                return true;

            if (cc(geom, frame, "geom", &G.forearmRoll_, tfForearmRollLink(), "forearmRoll", req, res, report))
                return true;
            
            if (cc(geom, frame, "geom", &G.wristFlex_, tfWristFlexLink(), "wristFlex", req, res, report))
                return true;

            if (cc(geom, frame, "geom", &G.wristRoll_, tfWristRollLink(), "wristRoll", req, res, report))
                return true;

            if (cc(geom, frame, "geom", &G.gripper_, tfGripperLink(), "gripper", req, res, report))
                return true;

            if (cc(geom, frame, "geom", &G.neck_, tfNeckLink(), "neck", req, res, report))
                return true;
            
            if (cc(geom, frame, "geom", &G.head_, tfHeadLink(), "head", req, res, report))
                return true;

            return false;
        }

        template <class Char, class Traits, class Geom>
        void renderCG(BlenderPy<Char, Traits> bpy, const Geom& geom, const Frame& frame, const char *name) const {
            Eigen::IOFormat fmt(Eigen::StreamPrecision, Eigen::DontAlignCols, ", ", ", ");
            Eigen::AngleAxis<S> aa{frame.linear()};

            if constexpr (std::is_same_v<fcl::Capsule<S>, Geom> ||
                          std::is_same_v<fcl::Cylinder<S>, Geom>)
            {
                bpy << "bpy.ops.mesh.primitive_cylinder_add("
                    "vertices=24, radius=" << geom.radius << ", depth=" << geom.lz << ", "
                    "view_align=False, enter_editmode=False, location=("
                    << frame.translation().format(fmt) << "))";
            }
            if constexpr (std::is_same_v<fcl::Box<S>, Geom>)
            {
                bpy << "bpy.ops.mesh.primitive_cube_add(size=1.0, view_align=False, enter_editmode=False, location=(" << frame.translation().format(fmt) << "))";
                bpy << "bpy.ops.transform.resize(value=(" << geom.side.format(fmt) << "))";
                
            }
            bpy << "bpy.context.object.name = \"" << name << "\"";
            bpy << "bpy.context.object.rotation_mode = 'AXIS_ANGLE'";
            bpy << "bpy.context.object.rotation_axis_angle = ("
                << aa.angle() << ", " << aa.axis().format(fmt) << ")";
        }

        template <class Char, class Traits>
        void toCollisionGeometryBlenderScript(BlenderPy<Char, Traits> bpy) const {
            const auto& G = collisionGeometry();
            renderCG(bpy, G.base_, tfBaseLink(), "base");
            renderCG(bpy, G.torsoLift_, tfTorsoLiftLink(), "torsoLift");
            renderCG(bpy, G.shoulderPan_, tfShoulderPanLink(), "shoulderPan");
            renderCG(bpy, G.shoulderLift_, tfShoulderLiftLink(), "shoulderLift");
            renderCG(bpy, G.upperarmRoll_, tfUpperarmRollLink(), "upperarmRoll");
            renderCG(bpy, G.elbowFlex_, tfElbowFlexLink(), "elbowFlex");
            renderCG(bpy, G.forearmRoll_, tfForearmRollLink(), "forearmRoll");
            renderCG(bpy, G.wristFlex_, tfWristFlexLink(), "wristFlex");
            renderCG(bpy, G.wristRoll_, tfWristRollLink(), "wristRoll");
            renderCG(bpy, G.gripper_, tfGripperLink(), "gripperLink");
            renderCG(bpy, G.neck_, tfNeckLink(), "neck");
            renderCG(bpy, G.head_, tfHeadLink(), "head");
        }

        template <class Char, class Traits>
        void toArticulatedBlenderScript(BlenderPy<Char, Traits> bpy, const std::string& meshPath) const {
            // TODO: these transforms are COPIED! from fk().  The should be SHARED with fk().
            static const std::vector<BPYLink<S>> links{{
                { "", "base", 0, 0, 0 },
                { "base", "torso_lift", -0.086875, 0, 0.37743 },
                { "torso_lift", "shoulder_pan", 0.119525, 0, 0.34858 },
                { "shoulder_pan", "shoulder_lift", 0.117, 0, 0.0599999999999999 },
                { "shoulder_lift", "upperarm_roll", 0.219, 0, 0 },
                { "upperarm_roll", "elbow_flex", 0.133, 0, 0 },
                { "elbow_flex", "forearm_roll", 0.197, 0, 0 },
                { "forearm_roll", "wrist_flex", 0.1245, 0, 0 },
                { "wrist_flex", "wrist_roll", 0.1385, 0, 0 },
                { "wrist_roll", "gripper", 0.16645, 0, 0 },
                { "torso_lift", "head_pan", 0.053125, 0, 0.603001417713939 },
                { "head_pan", "head_tilt", 0.14253, 0, 0.057999 },
                { "gripper", "l_gripper_finger", 0, -0.101425, 0 }, // 0, -0.015425, 0 },
                { "gripper", "r_gripper_finger", 0,  0.101425, 0 }, // 0,  0.015425, 0 },
            }};

            Eigen::IOFormat fmt{Eigen::FullPrecision, Eigen::DontAlignCols, ", ", ", ", "", "", "(", ")"};

            for (auto& link : links) {
                bpy << link << " = bpy.data.objects.new(\"" << link << "\", None)";
                bpy << link << ".rotation_mode = 'AXIS_ANGLE'";
                bpy << "bpy.context.collection.objects.link(" << link << ")";
                if ("gripper" == link.parent_) // the two fingers are in STL
                    bpy << "bpy.ops.import_mesh.stl(filepath=\"" << meshPath << link << "_link.STL\")";
                else
                    bpy << "bpy.ops.wm.collada_import(filepath=\"" << meshPath << link << "_link.dae\")";
                bpy << "for obj in bpy.context.selected_objects:";
                auto loop = bpy.indented();
                loop << "obj.constraints.new(type='CHILD_OF')";
                loop << "obj.constraints['Child Of'].target = " << link;

                if (!link.parent_.empty()) {
                    bpy << link << ".constraints.new(type='CHILD_OF')";
                    bpy << link << ".constraints['Child Of'].target = " << link.parent_;
                }

                bpy << link << ".location = " << link.location_.format(fmt);
            }

            bpy << "robot = [ \\";
            for (auto& link : links)
                bpy << "    " << link << ", \\";
            bpy << "]";
        }

        template <class Char, class Traits>
        void updateArticulatedBlenderScript(BlenderPy<Char, Traits> bpy) const {
            bpy << "torso_lift.location = (-0.086875, 0, " << (0.37743 + config_[kTorsoLiftJoint]) << ")";
            bpy << "shoulder_pan.rotation_axis_angle = (" << config_[kShoulderPanJoint] << ",0,0,1)";
            bpy << "shoulder_lift.rotation_axis_angle = (" << config_[kShoulderLiftJoint] << ",0,1,0)";
            bpy << "upperarm_roll.rotation_axis_angle = (" << config_[kUpperarmRollJoint] << ",1,0,0)";
            bpy << "elbow_flex.rotation_axis_angle = (" << config_[kElbowFlexJoint] << ",0,1,0)";
            bpy << "forearm_roll.rotation_axis_angle = (" << config_[kForearmRollJoint] << ",1,0,0)";
            bpy << "wrist_flex.rotation_axis_angle = (" << config_[kWristFlexJoint] << ",0,1,0)";
            bpy << "wrist_roll.rotation_axis_angle = (" << config_[kWristRollJoint] << ",1,0,0)";
        }

        template <class Char, class Traits>
        void keyframeInsert(BlenderPy<Char, Traits> bpy, int frame) const {
            bpy << "torso_lift.keyframe_insert(data_path='location', frame=" << frame << ")";
            bpy << "for obj in robot[2:9]:";
            bpy << "    obj.keyframe_insert(data_path='rotation_axis_angle', frame=" << frame << ")";
        }
    };
}

#endif
