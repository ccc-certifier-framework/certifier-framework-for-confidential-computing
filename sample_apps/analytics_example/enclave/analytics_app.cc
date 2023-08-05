


#include <dirent.h>

#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>

// For sample Applications
#include <DataFrame/DataFrame.h>                   // Main DataFrame header
#include <DataFrame/DataFrameFinancialVisitors.h>  // Financial algorithms
#include <DataFrame/DataFrameMLVisitors.h>     // Machine-learning algorithms
#include <DataFrame/DataFrameStatsVisitors.h>  // Statistical algorithms
#include <DataFrame/DataFrameStatsVisitors.h>
#include <DataFrame/RandGen.h>

using namespace hmdf;

using ULDataFrame = StdDataFrame<long>;

std::string proc_data(const char *sales_df_str) {
  std::cout << "=========" << std::endl;
  std::cout << "Starting Analytics Applicaton: " << std::endl;
  std::cout << "=========" << std::endl;
  std::string ret;

  // MyDataFrame df;
  ULDataFrame sales_df;
  sales_df.from_string(sales_df_str);

  // basic statistics
  MeanVisitor<double> n_mv;
  auto mean = sales_df.visit<double>("total_price", n_mv).get_result();
  ret.append("mean sale price is " + std::to_string(mean) + "\n");


  // calculate correlation
  CorrVisitor<double, double> corr_v;
  std::string                 sel_column_names[] = {"order_id",
                                    "product_id",
                                    "price_per_unit",
                                    "quantity",
                                    "total_price"};
  for (auto col_1 : sel_column_names) {
    ret.append(col_1 + " ");
    for (auto col_2 : sel_column_names) {
      auto corr =
          sales_df.visit<double, double>(col_1.c_str(), col_2.c_str(), corr_v)
              .get_result();
      ret.append(" " + std::to_string(corr) + " ");
    }
    ret.append("\n");
  }

  std::cout << "=========" << std::endl;
  std::cout << "Finished Data Analytics Application" << std::endl;
  std::cout << ret << std::endl;
  std::cout << "=========" << std::endl;

  return ret;
}
