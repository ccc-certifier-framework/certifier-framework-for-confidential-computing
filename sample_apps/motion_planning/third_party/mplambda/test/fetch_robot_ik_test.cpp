#include <mpl/demo/fetch_robot.hpp>
#include "test.hpp"

int main(int argc, char *argv[]) try {
    using S = double;
    using Robot = mpl::demo::FetchRobot<S>;
    using Config = Robot::Config;
    using Frame = Robot::Frame;
    
    Eigen::Matrix<S, 6, 1> L;
    L.fill(1);
    // L << 1, 1, 1, 0.01, 0.01, 0.01;

    S eps = 1e-3;
    // S dMax = 1.0;

    std::mt19937_64 rng;
    int solvedCount = 0;
    constexpr int ikProblems = 100;
    for (int qNo=0 ; qNo < ikProblems ; ++qNo) {
        Robot robot;
        Config q0 = Robot::randomConfig(rng);
        robot.setConfig(q0);
        
        Frame target = robot.getEndEffectorFrame();
        
        Config q1 = Robot::randomConfig(rng);
        // S d = (q1 - q0).norm();
        
        // if (d > dMax)
        //     q1 = q0 + (q1 - q0) * (dMax / d);
        
        robot.setConfig(q1);

        if (robot.ik(target, L, eps)) {
            // check that we reached the target frame from q1
            // EXPECT_THAT((target.matrix() - robot.getEndEffectorFrame().matrix()).norm()) < eps;
            S dPos = (L.asDiagonal() * mpl::demo::Twist<S>::diff(robot.getEndEffectorFrame(), target).matrix()).norm();
            EXPECT_THAT(dPos) < eps;
            // it is unlikely that we get the exact same configuration
            // from a IK random starting configuration.  If we got the
            // same one, then something is suspect.
            EXPECT_THAT((q1 - q0).cwiseAbs().maxCoeff()) > 1e-2;
            ++solvedCount;
        }
    }

    // expect that we solve at least 20% of these random IK problems.
    // These are random configurations to random end-effector pose
    // that is reachable.  The long distance from some of these makes
    // it likely that the LMA solver will go through a local minima
    // and not be able to reach the pose.  Higher percentage results
    // are possible with configurations that are closer to the
    // generating pose.
    EXPECT_THAT(solvedCount) > ikProblems * 20/100;

    std::clog << "solved " << solvedCount << " of " << ikProblems << std::endl;

    return EXIT_SUCCESS;
} catch (const std::exception& ex) {
    std::clog << ex.what() << std::endl;
    return EXIT_FAILURE;
}
