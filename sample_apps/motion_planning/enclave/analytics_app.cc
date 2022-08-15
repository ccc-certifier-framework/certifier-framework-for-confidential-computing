

#include <mpl/demo/lambda_common.hpp>
#include <mpl/demo/app_options.hpp>


std::string proc_data(const char* sales_df_str){
    mpl::demo::AppOptions options;
    mpl::demo::runSelectPlanner(options);
    return "ret";
}
