#include <mpl/demo/app_options.hpp>
#include <mpl/demo/se3_rigid_body_scenario.hpp>
#include <mpl/demo/fetch_scenario.hpp>
#include <mpl/prrt.hpp>
#include <mpl/comm.hpp>
#include <mpl/pcforest.hpp>
#include <mpl/option.hpp>
#include <getopt.h>
#include <optional>
#include <stdio.h>

namespace mpl::demo {

    template <class T, class U>
    struct ConvertState : std::false_type {};

    template <class R, class S>
    struct ConvertState<
        std::tuple<Eigen::Quaternion<R>, Eigen::Matrix<R, 3, 1>>,
        std::tuple<Eigen::Quaternion<S>, Eigen::Matrix<S, 3, 1>>>
        : std::true_type
    {
        using Result = std::tuple<Eigen::Quaternion<R>, Eigen::Matrix<R, 3, 1>>;
        using Source = std::tuple<Eigen::Quaternion<S>, Eigen::Matrix<S, 3, 1>>;
        
        static Result apply(const Source& q) {
            return Result(
                std::get<0>(q).template cast<R>(),
                std::get<1>(q).template cast<R>());
        }
    };

    template <class R, class S, int dim>
    struct ConvertState<Eigen::Matrix<R, dim, 1>, Eigen::Matrix<S, dim, 1>>
        : std::true_type
    {
        using Result = Eigen::Matrix<R, dim, 1>;
        using Source = Eigen::Matrix<S, dim, 1>;

        static Result apply(const Source& q) {
            return q.template cast<R>();
        }
    };


    template <class T, class Rep, class Period>
    void sendPath(Comm& comm, std::chrono::duration<Rep, Period> elapsed, T& solution) {
        using State = typename T::State;
        using Distance = typename T::Distance;
        
        if (comm) {
            std::vector<State> path;
            solution.visit([&] (const State& q) { path.push_back(q); });
            std::reverse(path.begin(), path.end());
            Distance cost = solution.cost();
            comm.sendPath(cost, elapsed, std::move(path));
        }
    }

    template <class Scenario, class Algorithm, class ... Args>
    void runPlanner(const demo::AppOptions& options, Args&& ... args) {
        printf("runing planner") ;
        JI_LOG(INFO) << "setting up planner";
        using State = typename Scenario::State;
        using Distance = typename Scenario::Distance;

        State qStart = options.start<State>();
        

        Comm comm_;
         
        if (options.coordinator(false).empty()) {
            //JI_LOG(WARN) << "no coordinator set";
        } else {
            //comm_.setProblemId(options.problemId());
            //comm_.connect(options.coordinator());
        }
        comm_.connect("128.32.37.34:16734");

        JI_LOG(INFO) << "setting up planner";
        
        try{
            Planner<Scenario, Algorithm> planner(std::forward<Args>(args)...);
        
        //JI_LOG(INFO) << "Adding start state: " << qStart;
        planner.addStart(qStart);
        

        //JI_LOG(INFO) << "Starting solve()";
        // using Clock = std::chrono::steady_clock;
        // Clock::duration maxElapsedSolveTime = std::chrono::duration_cast<Clock::duration>(
        //     std::chrono::duration<double>(options.timeLimit()));
        // auto start = Clock::now();
        // Clock::duration maxElapsedSolveTime = ;
        long long clock_counter = 0;

        // record the initial solution (it should not be an actual
        // solution).  We use this later to perform the C-FOREST path
        // update, and to check if we should write out one last
        // solution.
        auto solution = planner.solution();
        assert(!solution);

        if constexpr (Algorithm::asymptotically_optimal) {
            // asymptotically-optimal planner, run for the
            // time-limit, and update the graph with best paths
            // from the network.
            planner.solve([&] {
                // if (maxElapsedSolveTime.count() > 0 && Clock::now() - start > maxElapsedSolveTime)
                //     return true;
                clock_counter += 1;
                comm_.process(
                    [&] (auto cost, auto&& pktPath) {
                        using Path = std::decay_t<decltype(pktPath)>;
                        using PathState = typename Path::value_type;
                        if constexpr (std::is_same_v<State, PathState>) {
                            planner.addPath(cost, std::forward<decltype(pktPath)>(pktPath));
                        } else if constexpr (ConvertState<State,PathState>::value) {
                            std::vector<State> path;
                            path.reserve(pktPath.size());
                            for (auto& q : pktPath)
                                path.emplace_back(ConvertState<State,PathState>::apply(q));
                            planner.addPath(cost, std::move(path));
                        } else {
                            //JI_LOG(WARN) << "received incompatible path type!";
                            return;
                        }
                        
                        // update our best solution if it has the same
                        // cost as the solution we just got from a
                        // peer.  If we have a different solution,
                        // then we'll update and send the solution
                        // after the comm_.process().  This avoids
                        // re-broadcasting the same solution.
                        auto newSol = planner.solution();
                        if (newSol.cost() == cost)
                            solution = newSol;
                    });
                
                auto s = planner.solution();
                if (s < solution) {
                    sendPath(comm_, std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(clock_counter)), s);
                    solution = s;
                }
                
                return comm_.isDone();
            });
        } else {
            // non-asymptotically-optimal.  Stop as soon as we
            // have a solution (either locally or from the
            // network)
            planner.solve([&] {
                //if (maxElapsedSolveTime.count() > 0 && clock_counter > maxElapsedSolveTime)
                //    return true;
                comm_.process();
                return comm_.isDone() || planner.isSolved();
            });
        }
            
        
        JI_LOG(INFO) << "solution " << (planner.isSolved() ? "" : "not ") << "found";
        JI_LOG(INFO) << "graph size = " << planner.size();
        JI_LOG(INFO) << "samples (goal-biased, rejected) = " << planner.samplesConsidered() << " ("
                    << planner.goalBiasedSamples() << ", "
                    << planner.rejectedSamples() << ")";
            
        if (auto finalSolution = planner.solution()) {
            if (finalSolution != solution)
                sendPath(comm_, std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(clock_counter)), finalSolution);
            finalSolution.visit([] (const State& q) { 
            JI_LOG(INFO) << "  " << q; 
            });
        }
        }
        catch (std::exception& e){ printf("exception!!!"); }

#if 0   // write the end-effector vertices to stdout
        if constexpr (std::is_same_v<State, Eigen::Matrix<double, 8, 1>>) {
            // std::map<const State*, std::size_t> stateIndex;
            planner.visitTree([&] (const State& a, const State& b) {
                demo::FetchRobot<double> robot(a);
                Eigen::IOFormat fmt(Eigen::StreamPrecision, Eigen::DontAlignCols, " ", " ");
                std::cout << "v " << robot.getEndEffectorFrame().translation().format(fmt) << std::endl;
                // stateIndex.emplace(&a, stateIndex.size() + 1);
            });
            // planner.visitTree([&] (const State& a, const State& b) {
            //     auto ait = stateIndex.find(&a);
            //     auto bit = stateIndex.find(&b);
            //     std::cout << "l " << ait->second << " " << bit->second << " " << ait->second << std::endl;
            // });
        }
#endif

        comm_.sendDone();
    }


    template <class Algorithm, class S>
    void runSelectScenario(const demo::AppOptions& options) {
        //JI_LOG(INFO) << "running scenario: " << options.scenario();
        printf("run scenario %s\n", options.scenario().c_str()) ;
        if (options.scenario() == "se3") {
            printf("scenario 0");
            
            using Scenario = mpl::demo::SE3RigidBodyScenario<S>;
            using Bound = typename Scenario::Bound;
            using State = typename Scenario::State;
            State goal = options.goal<State>();
            
            Bound min = options.min<Bound>();
            Bound max = options.max<Bound>();
            
            runPlanner<Scenario, Algorithm>(
                options, options.env(), options.robot(), goal, min, max,
                options.checkResolution(0.1)); 
        } else if (options.scenario() == "fetch") {
            using Scenario = mpl::demo::FetchScenario<S>;
            using State = typename Scenario::State;
            using Frame = typename Scenario::Frame;
            using GoalRadius = Eigen::Matrix<S, 6, 1>;
            Frame envFrame = options.envFrame<Frame>();
            Frame goal = options.goal<Frame>();
            GoalRadius goalRadius = options.goalRadius<GoalRadius>();
            //JI_LOG(INFO) << "Env frame: " << envFrame;
            //JI_LOG(INFO) << "Goal: " << goal;
            goal = envFrame * goal;
            //JI_LOG(INFO) << "Goal in robot's frame: " << goal;
            runPlanner<Scenario, Algorithm>(
                options, envFrame, options.env(), goal, goalRadius,
                options.checkResolution(0.1));
        } else {
            printf("bad argument");
            throw std::invalid_argument("bad scenario: " + options.scenario());
        }
    }

    template <class Algorithm>
    void runSelectPrecision(const demo::AppOptions& options) {
        // TODO: revert this.  For now keeping it out the float branch
        // should double the compilation speed.
        
        // if (options.singlePrecision()) {
        //     runSelectScenario<Algorithm, float>(options);
        // } else {
        // //JI_LOG(INFO) << "using precision: double";
        printf("run scenario\n") ;
        runSelectScenario<Algorithm, double>(options);
        // }
    }

    void runSelectPlanner(const demo::AppOptions& options) {
        printf("hellooooooooooooooooooooooo\n") ;
        printf("%s\n", options.algorithm_.c_str()) ;
        // //JI_LOG(INFO) << "using planner: " << options.algorithm_;
        if (options.algorithm() == "rrt")
            runSelectPrecision<mpl::PRRT>(options);
        else if (options.algorithm() == "cforest")
            runSelectPrecision<mpl::PCForest>(options);
        else
            throw std::invalid_argument("unknown algorithm: " + options.algorithm()); 
    }
}
