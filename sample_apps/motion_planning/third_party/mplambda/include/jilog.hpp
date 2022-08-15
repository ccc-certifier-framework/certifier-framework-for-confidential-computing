#ifndef JI_LOG_HPP
#define JI_LOG_HPP

#include <chrono>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <tuple>
#include <Eigen/Dense>

namespace jilog_impl {
    // enum Level {
    //     TRACE,
    //     DEBUG,
    //     INFO,
    //     WARN,
    //     ERROR,
    //     FATAL
    // };

#define DEFINE_LOG_LEVEL(Level) \
    struct Level {                                                      \
        template <class Char, class Traits>                             \
        friend decltype(auto) operator << (std::basic_ostream<Char, Traits>& out, const Level& level) { \
            return out << #Level;                                       \
        }                                                               \
    };
    DEFINE_LOG_LEVEL(TRACE)
    DEFINE_LOG_LEVEL(DEBUG)
    DEFINE_LOG_LEVEL(INFO)
    DEFINE_LOG_LEVEL(WARN)
    DEFINE_LOG_LEVEL(ERROR)
    DEFINE_LOG_LEVEL(FATAL)
#undef DEFINE_LOG_LEVEL

    template <class T>
    constexpr T log10(T value) {
        return (value > 1 ? log10(value/10) + 1 : 0);
    }
    
    class LogStream {
        std::ostringstream msg_;

        // static std::string levelName(Level level) {
        //     switch (level) {
        //     case TRACE: return "TRACE";
        //     case DEBUG: return "DEBUG";
        //     case INFO:  return "INFO";
        //     case WARN:  return "WARN";
        //     case ERROR: return "ERROR";
        //     case FATAL: return "FATAL";
        //     default:    return "[" + std::to_string(level) + "]";
        //     }
        // }

        template <std::size_t I, class T>
        void ith(const T& t) {
            if (I) msg_ << ", ";
            *this << std::get<I>(t);
        }

        template <class T, std::size_t ... I>
        void append(const T& t, std::index_sequence<I...>) {
            msg_ << '{';
            (ith<I>(t), ...);
            msg_ << '}';
        }
        
    public:
        template <class Level>
        inline LogStream(Level level, const char *file, unsigned line, const char *fn) {
            // using Clock = std::chrono::system_clock;
            // auto now = Clock::now();
            // std::time_t t = Clock::to_time_t(now);
            // auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
            //     now.time_since_epoch()).count() % 1000;

            // msg_ << std::put_time(std::localtime(&t), "%T") << '.'
            //      << std::setfill('0') << std::setw(3) << millis << ' '
            //      << std::setfill(' ') << std::left << std::setw(5) << level
            //      << " (" << file << ':' << line << ") ";
            // msg_ << " (" << file << ':' << line << ") ";
        }

        inline ~LogStream() {
            //msg_ << '\n';
            //std::clog << msg_.str();
            printf("%s\n", msg_.str().c_str());
        }

        template <typename U>
        std::enable_if_t<
            !std::is_base_of_v<Eigen::DenseBase<std::decay_t<U>>, std::decay_t<U>> &&
            !std::is_base_of_v<Eigen::QuaternionBase<std::decay_t<U>>, std::decay_t<U>>,
            LogStream&>
        operator << (const U& arg) {
            msg_ << arg;
            return *this;
        }

        template <class T>
        LogStream& operator << (const std::optional<T>& opt) {
            if (opt)
                *this << opt.value();
            else
                msg_ << "{}";
            return *this;
        }

        template <class S, int d, int m, int o>
        LogStream& operator << (const Eigen::Transform<S,d,m,o>& t) {
            Eigen::IOFormat fmt(Eigen::StreamPrecision, 0, " ", "\n\t", "", "", "", "");
            msg_ << "\n\t" << t.matrix().format(fmt);
            return *this;
        }

        template <class D>
        LogStream& operator << (const Eigen::QuaternionBase<D>& q) {
            Eigen::IOFormat fmt(Eigen::FullPrecision, Eigen::DontAlignCols, " ", " ", "", "", "", "");
            msg_ << "q{" << q.coeffs().transpose().format(fmt) << "}";
            return *this;
        }

        template <class D>
        LogStream& operator << (const Eigen::MatrixBase<D>& m) {
            Eigen::IOFormat fmt(Eigen::FullPrecision, Eigen::DontAlignCols, ", ", ",  ", "", "", "[", "]");                                    
            if (m.cols() == 1)
                msg_ << m.transpose().format(fmt) << "^T";
            else
                msg_ << m.format(fmt);
            return *this;
        }

        template <class ... T>
        LogStream& operator << (const std::tuple<T...>& arg) {
            append(arg, std::index_sequence_for<T...>{});
            return *this;
        }

        template <class Rep, class Period>
        LogStream& operator << (const std::chrono::duration<Rep, Period>& d) {
            if constexpr (std::is_integral_v<Rep> && Period::num == 1 && Period::den % 10  == 0 && Period::den > 1) {
                // output directly as an integer if easy to do.  This
                // route keeps precision, and may be faster.
                msg_ << d.count() / static_cast<Rep>(Period::den) << '.';
                auto oldFill = msg_.fill('0');
                auto oldWidth = msg_.width(log10(Period::den));
                auto oldPos = msg_.setf(std::ios_base::right, std::ios_base::adjustfield);
                msg_ << d.count() % Period::den;
                msg_.fill(oldFill);
                msg_.width(oldWidth);
                msg_.setf(oldPos, std::ios_base::adjustfield);
                msg_ << " s";
            } else {
                // otherwise convert to double and output.  This
                // typically loses some precision (mostly due to
                // formatting, but also after 104 days with
                // 64-bit nanoseconds)
                msg_ << std::chrono::duration<double>(d).count() << " s";
            }
            return *this;
        }
    };
}

#define JI_LOG(level) ::jilog_impl::LogStream( \
        ::jilog_impl:: level{}, __FILE__, __LINE__, __FUNCTION__)

#endif
