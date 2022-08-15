#include <mpl/demo/app_options.hpp>
#include <getopt.h>
#include <iostream>

float mpl::demo::OptionParser<float>::parse(
    const std::string& name, const char *arg, char **endp)
{
    if (!*arg)
        throw std::invalid_argument(name + " is required");
    
    float v = std::strtof(arg, endp);
    if (*endp == arg)
        throw std::invalid_argument("bad value for " + name + ": " + arg);
    return v;
}

double mpl::demo::OptionParser<double>::parse(
    const std::string& name, const char *arg, char **endp)
{
    if (!*arg)
        throw std::invalid_argument(name + " is required");
    
    float v = std::strtod(arg, endp);
    if (*endp == arg)
        throw std::invalid_argument("bad value for " + name + ": " + arg);
    return v;
}

void mpl::demo::AppOptions::usage(const char *argv0) {
    std::cerr << "Usage: " << argv0 << R"( [options]
Options:
  -S, --scenario=(se3|fetch)    Set the scenario to run
  -a, --algorithm=(rrt|cforest) Set the algorithm to run
  -c, --coordinator=HOST:PORT   Specify the coordinator's host.  Port is optional.
  -j, --jobs=COUNT              Specify the number of simultaneous lambdas to run
  -I, --problem-id=ID           (this is for internal use only)
  -t, --time-limit=TIME         Specify the time limit of each lambda in seconds
  -e, --env=MESH                The environment mesh to use (valid for se3 and fetch)
  -E, --env-frame=X,Y,theta     The translation and rotation to apply to the environment (fetch only)
  -r, --robot=MESH              The robot's mesh (se3 only)
  -s, --start=W,I,J,K,X,Y,Z     The start configuration (se3 = rotation + translation, fetch = configuration)
  -g, --goal=W,I,J,K,X,Y,Z      (may be in joint space or IK frame)
  -G, --goal-radius=RADIUS      Specify the tolerances for the goal as either a scalar or twist (fetch only)
  -m, --min=X,Y,Z               Workspace minimum (se3 only)
  -M, --max=X,Y,Z               Workspace maximum (se3 only)
  -d, --check-resolution=DIST   Collision checking resolution (0 means use default)
  -f, --float                   Use single-precision math instead of double (not currently enabled)
  -T, --thread_id=thread_id     Needed if multiple anna clients are running from the same machine (might only be needed on localhost). Each thread_id should be unique.
)";
}

/*
mpl::demo::AppOptions::AppOptions(hello_world::MP_Lambda_Input lambda_input) {

    if(!lambda_input.scenario().empty()){
        scenario_ = lambda_input.scenario(); 
    }

    if(!lambda_input.algorithm().empty()){
        algorithm_ =  lambda_input.algorithm(); 
    }

    if(!lambda_input.coordinator().empty()){
        coordinator_ =  lambda_input.coordinator(); 
    }

    if(!lambda_input.jobs().empty()){
        jobs_ = stoi(lambda_input.jobs());
        if (jobs_ > MAX_JOBS)
                    throw std::invalid_argument("bad value for --jobs");
    }

    if(!lambda_input.env().empty()){
        env_ = lambda_input.env();
    }
    if(!lambda_input.env_frame().empty()){
        envFrame_ = lambda_input.env_frame();
    }
    if(!lambda_input.robot().empty()){
        robot_ = lambda_input.robot();
    }
    if(!lambda_input.goal().empty()){
        goal_ = lambda_input.goal();
    }

    if(!lambda_input.goal_radius().empty()){
        goalRadius_ = lambda_input.goal_radius();
    }

    if(!lambda_input.start().empty()){
        start_ = lambda_input.start();
    }

    if(!lambda_input.min().empty()){
        min_ = lambda_input.min();
    }

    if(!lambda_input.max().empty()){
        max_ = lambda_input.max();
    }

    if(!lambda_input.problem_id().empty())
        problemId_ = stoi(lambda_input.problem_id());
    
    if(!lambda_input.time_limit().empty()){
        timeLimit_ = stod(lambda_input.time_limit());
        if (timeLimit_ < 0)
            throw std::invalid_argument("bad value for --time-limit");
    }

    if(!lambda_input.check_resolution().empty()){
        checkResolution_ = stod(lambda_input.check_resolution());
        if (checkResolution_ < 0)
                throw std::invalid_argument("bad value for --check-resolution");
    }  
}
*/

static void put(std::vector<std::string>& args, const std::string& key, const std::string& value) {
    if (!value.empty()) {
        args.push_back(key);
        args.push_back(value);
    }
}

mpl::packet::Problem mpl::demo::AppOptions::toProblemPacket() const {
    std::vector<std::string> args;
    args.reserve(26);
    put(args, "scenario", scenario());
    put(args, "coordinator", coordinator());
    put(args, "time-limit", std::to_string(timeLimit_));
    put(args, "check-resolution", std::to_string(checkResolution_));
    put(args, "env", env_);
    put(args, "env-frame", envFrame_);
    put(args, "robot", robot_);
    put(args, "start", start_);
    put(args, "goal", goal_);
    put(args, "goal-radius", goalRadius_);
    put(args, "min", min_);
    put(args, "max", max_);
    // TODO: args.push_back("single-precision");

    std::uint8_t alg;
    if ("rrt" == algorithm_) {
        alg = 'r';
    } else if ("cforest" == algorithm_) {
        alg = 'c';
    } else {
        throw std::invalid_argument("bad algorithm");
    }
    
    return mpl::packet::Problem(jobs_, alg, std::move(args));
}

