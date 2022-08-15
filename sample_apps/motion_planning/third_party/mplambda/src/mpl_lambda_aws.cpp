#include <mpl/demo/lambda_common.hpp>
// main.cpp
#include <aws/lambda-runtime/runtime.h>
#include <aws/core/Aws.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <iostream>
#include <memory>
#include <string>
#include <iostream>

using namespace aws::lambda_runtime;

static void assign_value(std::string& value, const std::string& s) { value = s; }
static void assign_value(double& value, const std::string& s) { value = std::stod(s); }
static void assign_value(std::uint64_t& value, const std::string& s) { value = std::stoull(s); }

template <class T, class J>
static void set(T& value, const J& json, const std::string& name) {
    Aws::String name_aws(name.c_str(), name.size());
    if (json.ValueExists(name_aws)) {
        Aws::String aws_s = json.GetString(name_aws);
        std::string s(aws_s.c_str(), aws_s.size());
        assign_value(value, s);
    }
}

invocation_response my_handler(invocation_request const& request) try {
    using namespace Aws::Utils::Json;
    Aws::String payload(request.payload.c_str(), request.payload.size());
    JsonValue json(payload);
    
    if (!json.WasParseSuccessful()) {
        return invocation_response::failure("Failed to parse input JSON", "InvalidJSON");
    }

    auto v = json.View();

    mpl::demo::AppOptions options;
    set(options.scenario_, v, "scenario");
    set(options.coordinator_, v, "coordinator");
    set(options.start_, v, "start");
    set(options.goal_, v, "goal");
    set(options.min_, v, "min");
    set(options.max_, v, "max");
    set(options.algorithm_, v, "algorithm");
    set(options.env_, v, "env");
    set(options.robot_, v, "robot");
    set(options.envFrame_, v, "env-frame");
    set(options.goalRadius_, v, "goal-radius");
    set(options.timeLimit_, v, "time-limit");
    set(options.checkResolution_, v, "check-resolution");
    set(options.problemId_, v, "problem-id");

    mpl::demo::runSelectPlanner(options);
    return invocation_response::success("Solved!", "application/json");
} catch (const std::invalid_argument& ex) {
    std::cerr << "Invalid argument: " << ex.what() << std::endl;
    return invocation_response::failure(ex.what(), "InvalidArgument");
} catch (const std::exception& ex) {
    std::cerr << "Error: " << ex.what() << std::endl;
    return invocation_response::failure(ex.what(), "Exception");
}

int main()
{
    run_handler(my_handler);
    return 0;
}

