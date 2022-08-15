#pragma once
#ifndef MPL_PLANNER_HPP
#define MPL_PLANNER_HPP

namespace mpl {
    template <class Scenario, class Algorithm>
    class Planner;
}

#ifdef USE_OPENMP
#include <omp.h>
namespace mpl {
    inline int getMaxThreads() {
        return std::max(1, omp_get_max_threads());
    }
}
#else
#include <thread>
#include <cstdlib>
#include <iostream>
namespace mpl {
    inline int getMaxThreads() {
        // n can be zero when it cannot be determined.
        int n = std::thread::hardware_concurrency();
        if (char *ompNum = getenv("OMP_NUM_THREADS")) {
            char *end;
            errno = 0; // strtol will set to non-zero on error
            int num = (int)std::strtol(ompNum, &end, 0);
            if (errno == 0 && *end == '\0' && num > 0)
                return n ? std::min(num, n) : num;
            std::clog << "WARNING: bad value for OMP_NUM_THREADS" << std::endl;
        }
        return std::max(1, n);
    }
}
#endif


#endif
