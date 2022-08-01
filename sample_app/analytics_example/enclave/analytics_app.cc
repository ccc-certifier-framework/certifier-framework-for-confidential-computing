


#include <dirent.h> 

#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>

// For sample Applications 
#include <DataFrame/DataFrame.h>  // Main DataFrame header
#include <DataFrame/DataFrameFinancialVisitors.h>  // Financial algorithms
#include <DataFrame/DataFrameMLVisitors.h>  // Machine-learning algorithms
#include <DataFrame/DataFrameStatsVisitors.h>  // Statistical algorithms
#include <DataFrame/DataFrameStatsVisitors.h>
#include <DataFrame/RandGen.h>

using namespace hmdf;

// typedef StdDataFrame<time_t> MyDataFrame;
// using StrDataFrame = StdDataFrame<std::string>;

// // A DataFrame with ulong index type
// //
// using ULDataFrame = StdDataFrame<unsigned long>;

// // A DataFrame with string index type
// //
using StrDataFrame = StdDataFrame<std::string>;
using ULDataFrame = StdDataFrame<long>;
typedef StdDataFrame<time_t> MyDataFrame;


std::string proc_data(std::string root_dir, const char* sales_df_str){
    std::cout << "========="   << std::endl;  
    std::cout << "Starting Analytics Applicaton: "   << std::endl;
    std::cout << "========="   << std::endl;  
    std::string ret;

    //MyDataFrame df;
    try{

        ULDataFrame    customer_df, order_df, prod_df, sales_df;

        // Also, you can load data into a DataFrame from a file, suporting a few
        // different formats.
        // If the file cannot be found, an exception will be thrown.
        // If the DataFrame root directory is your current directory when running
        // this, it should work fine.
        //
        
        // customer_df.read((root_dir + "customers.csv").c_str(), io_format::csv2);
        // order_df.read((root_dir + "orders.csv").c_str(), io_format::csv2);
        // prod_df.read((root_dir + "products.csv").c_str(), io_format::csv2);
        // sales_df.read((root_dir + "sales.csv").c_str(), io_format::csv2);
        
        sales_df.from_string(sales_df_str);
        // merging by index 
        // ULDataFrame cop_data = customer_df
        //       .join_by_index<ULDataFrame, std::string, long, DateTime>(order_df, join_policy::left_right_join)
        //       .join_by_index<ULDataFrame, std::string, long, DateTime>(prod_df, join_policy::left_right_join);
        
        // std::string s = cop_data.to_string<std::string, long, DateTime> (io_format::csv);
        // printf("size: %d", customer_df.get_column<std::string>("customer_name").size()); 
        // printf ("string: %s", s.subslongtr(0, 1000).c_str()); 
        
        // basic statistics 
        MeanVisitor<double> n_mv;
        auto mean = sales_df.visit<double>("total_price", n_mv).get_result();
        ret.append("mean sale price is " + std::to_string(mean) + "\n"); 


        // calculate correlation
        CorrVisitor<double, double> corr_v;
        std::string sel_column_names[] = {"order_id", "product_id",  
                                          "price_per_unit", "quantity", "total_price"};
        for(auto col_1 : sel_column_names){
          ret.append(col_1 + " "); 
          for(auto col_2 : sel_column_names){
            auto corr = sales_df.visit<double, double>
                    (col_1.c_str(), col_2.c_str(), corr_v).get_result(); 
            ret.append(" " + std::to_string(corr) + " "); 
          }
          ret.append("\n");
        }

        std::cout << "========="   << std::endl;  
        std::cout << "Finished Data Analytics Application"   << std::endl;  
        std::cout << ret << std::endl;
        std::cout << "========="   << std::endl;  
    } catch (const std::exception &exc) {
        std::cout << "EXCEPTION================" << exc.what();
    }
    
    return ret;
}
