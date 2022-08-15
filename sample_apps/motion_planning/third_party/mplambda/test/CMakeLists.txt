# 3.10 introduces C++ 17 support
cmake_minimum_required (VERSION 3.10)
project (mpt_test)

# Enable C++17 (required for MPT)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Disable extensions to keep compatible with standards
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Eigen3 3.3 REQUIRED NO_MODULE)

file(GLOB files "*_test.cpp")
foreach(file ${files})
    get_filename_component(test_name ${file} NAME_WE)
    # Add the executable based upon the test source
    add_executable(${test_name} ${file})
    target_link_libraries(${test_name} Eigen3::Eigen)
    
    # Add a custom command for the test's output (.log), making sure
    # that it depends on the test executable.
    add_custom_command(
        OUTPUT  ${test_name}.log
        COMMAND ${test_name} | tee ${test_name}.tmp && mv ${test_name}.tmp ${test_name}.log
        DEPENDS ${test_name}
        COMMENT "TESTING ${test_name}")

    # Add the test to the top-level 'all' target
    add_custom_target(run_${test_name} ALL DEPENDS ${test_name}.log)
endforeach()
