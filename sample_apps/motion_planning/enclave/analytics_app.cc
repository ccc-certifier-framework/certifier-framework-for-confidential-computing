

#include <mpl/demo/lambda_common.hpp>
#include <mpl/demo/app_options.hpp>

std::string proc_data(const char* client_options){
    
    //parsing client options 
    motion_planning_task mpt; 
    mpt.ParseFromString(client_options);
    mpl::demo::AppOptions options;
    options.scenario_ = mpt.scenario();
    options.algorithm_ = mpt.algorithm();
    options.env_ = mpt.env();
    options.robot_ = mpt.robot();
    options.start_ = mpt.start();
    options.goal_ = mpt.goal();
    options.min_ = mpt.min();
    options.max_ = mpt.max();

    //run motion planner app
    mpl::demo::runSelectPlanner(options);
    return "ret";
}
