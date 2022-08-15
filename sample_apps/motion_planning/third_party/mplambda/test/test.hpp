#pragma once
#include <stdexcept>
#include <cassert>
#include <sstream>

namespace test {
    struct Failed : std::runtime_error {
        explicit Failed(const std::string& msg)
            : std::runtime_error(msg) {}
    };
    
    template <class T>
    class Expect {
        T value_;
        const char *expr_;
        const char *file_;
        int line_;
        mutable bool checked_{false};

    public:
        Expect(const T& value, const char *expr, const char *file, int line)
            : value_(value), expr_(expr), file_(file), line_(line) {}

        ~Expect() { assert(checked_); }
        
#define DEFINE_OPERATOR(OP)                                             \
        void operator OP (const T& expect) const {                      \
            checked_ = true;                                            \
            if (!(value_ OP expect)) {                                  \
                std::ostringstream str;                                 \
                str << file_ << ":" << line_ << ": expected `" << expr_ << "` " #OP " " << expect << ", got " << value_; \
                throw Failed(str.str());                                \
            }                                                           \
        }
        
        DEFINE_OPERATOR(==)
        DEFINE_OPERATOR(<)
        DEFINE_OPERATOR(>)
#undef DEFINE_OPERATOR
        
    };
};

#define EXPECT_THAT(expr) ::test::Expect(expr, #expr, __FILE__, __LINE__)
