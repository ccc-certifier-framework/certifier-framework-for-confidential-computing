#pragma once
#ifndef MPL_SYSERR_HPP
#define MPL_SYSERR_HPP

#include <system_error>
#include <sys/errno.h>

namespace mpl {
    inline auto syserr(const std::string& msg) {
        return std::system_error(errno, std::system_category(), msg);
    }
}

#endif
