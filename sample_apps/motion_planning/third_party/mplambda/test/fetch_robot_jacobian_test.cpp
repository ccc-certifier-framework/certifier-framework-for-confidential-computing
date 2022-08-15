#include <mpl/demo/fetch_robot.hpp>
#include <random>
#include "test.hpp"

int main(int argc, char *argv[]) try {
    using S = double;
    using Robot = mpl::demo::FetchRobot<S>;
    using Config = Robot::Config;
    using Frame = Robot::Frame;

    static constexpr S eps = 1e-6;
    
    std::mt19937_64 rng;
    for (int qNo=0 ; qNo < 1000 ; ++qNo) {
        Robot robot;
        Config q0 = Robot::randomConfig(rng);
        robot.setConfig(q0);

        auto J = robot.jacobian();

        Frame tf0 = robot.getEndEffectorFrame();

        for (std::size_t j = 0 ; j<Robot::kDOF ; ++j) {
            Config qj = q0;
            qj[j] += eps;
            robot.setConfig(qj);
            Frame tfj = robot.getEndEffectorFrame();
            Eigen::AngleAxis<S> aa(tf0.linear().transpose() * tfj.linear());
            Eigen::Matrix<S, 3, 1> tj = (tfj.translation() - tf0.translation()) / eps;
            Eigen::Matrix<S, 3, 1> rj = tf0.linear() * (aa.axis() * (aa.angle() / eps));
            // std::cout << "j = " << j << ", J.col(j) = " <<
            //     J.template block<3,1>(3, j).transpose() <<
            //     ", tj = " << rj.transpose() << std::endl;
            // std::cout << tfj.matrix() << std::endl;
            EXPECT_THAT((J.template block<3,1>(0, j) - tj).cwiseAbs().maxCoeff()) < eps;
            EXPECT_THAT((J.template block<3,1>(3, j) - rj).cwiseAbs().maxCoeff()) < eps;
        }
    }
    return EXIT_SUCCESS;
} catch (const std::exception& ex) {
    std::clog << "test failed with exception: " << ex.what() << std::endl;
    return EXIT_FAILURE;
}
