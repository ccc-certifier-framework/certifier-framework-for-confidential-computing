#pragma once
#ifndef MPL_BUFFER_HPP
#define MPL_BUFFER_HPP

#include <vector>
#include <cassert>
#include <Eigen/Dense>

namespace mpl {
    template <class T, bool enable = std::is_arithmetic_v<T>>
    struct primitive_buffer_size;

    template <class T>
    struct primitive_buffer_size<T, true> {
        static constexpr std::size_t value = sizeof(T);
    };

    template <class T>
    struct buffer_size : primitive_buffer_size<T> {};

    template <class S, int dim>
    struct buffer_size<Eigen::Matrix<S, dim, 1>> {
        static constexpr std::size_t value = buffer_size<S>::value * dim;
    };

    template <class S>
    struct buffer_size<Eigen::Quaternion<S>> {
        static constexpr std::size_t value = buffer_size<S>::value * 4;
    };

    template <class ... T>
    struct buffer_size<std::tuple<T...>> {
        static constexpr std::size_t value = (buffer_size<T>::value + ...);
    };

    template <class T>
    constexpr std::size_t buffer_size_v = buffer_size<T>::value;

    class BufferView {
    protected:
        char *position_;
        char *limit_;
    public:
        BufferView()
            : position_{nullptr}
            , limit_{nullptr}
        {
        }

        BufferView(const BufferView& other)
            : position_(other.position_)
            , limit_(other.limit_)
        {
        }

    protected:
        BufferView(char *position, char *limit)
            : position_(position)
            , limit_(limit)
        {
        }
        
        BufferView(std::size_t n)
            : position_(new char[n])
            , limit_(position_ + n)
        {
        }

        BufferView(BufferView&& other)
            : position_{std::exchange(other.position_, nullptr)}
            , limit_{std::exchange(other.limit_, nullptr)}
        {
        }

    public:
        char* begin() {
            return position_;
        }
        
        const char* begin() const {
            return position_;
        }

        char* end() {
            return limit_;
        }

        const char *end() const {
            return limit_;
        }

        std::size_t remaining() const {
            return std::distance(position_, limit_);
        }

    private:
        template <class T>
        static std::enable_if_t<std::is_arithmetic_v<T>>
        decode(T& value, const char *p) {
            if (__ORDER_BIG_ENDIAN__ == __BYTE_ORDER__) {
                std::copy(p, p+sizeof(T), reinterpret_cast<char*>(&value));
            } else {
                std::reverse_copy(p, p+sizeof(T), reinterpret_cast<char*>(&value));
            }            
        }

        template <class S, int dim>
        static void decode(Eigen::Matrix<S, dim, 1>& v, const char *p) {
            for (int i=0 ; i<dim ; ++i)
                decode(v[i], p + i*sizeof(S));
        }

        template <class S>
        static void decode(Eigen::Quaternion<S>& q, const char *p) {
            decode(q.coeffs(), p);
        }

        template <class T>
        static void decode(T& tuple, const char *p, std::index_sequence<>) {
        }

        template <class T, std::size_t I, std::size_t ... J>
        static void decode(T& tuple, const char *p, std::index_sequence<I, J...>) {
            decode(std::get<I>(tuple), p);
            decode(tuple, p + buffer_size_v<std::tuple_element_t<I, T>>, std::index_sequence<J...>{});
        }

        template <class ... T>
        static void decode(std::tuple<T...>& tuple, const char *p) {
            decode(tuple, p, std::index_sequence_for<T...>{});
        }

    public:
        template <class T>
        T peek(int offset = 0) const {
            T value;
            decode(value, begin() + offset);
            return value;
        }

        template <class T>
        T get() {
            T value;
            decode(value, begin());
            position_ += buffer_size_v<T>;
            return value;
        }

        std::string getString(std::size_t n) {
            std::string str{position_, position_ + n};
            position_ += n;
            assert(position_ <= limit_);
            return str;
        }

        std::string getString() {
            std::string str{position_, limit_};
            position_ = limit_;
            return str;
        }

        template <class T>
        std::enable_if_t<std::is_arithmetic_v<T>>
        put(const T& value) {
            assert(position_ + sizeof(T) <= limit_);
            const char *p = reinterpret_cast<const char *>(&value);
            if (__ORDER_BIG_ENDIAN__ == __BYTE_ORDER__) {
                std::copy(p, p+sizeof(T), position_);
            } else {
                std::reverse_copy(p, p+sizeof(T), position_);
            }
            position_ += sizeof(T);
        }

        template <class S, int dim>
        void put(const Eigen::Matrix<S, dim, 1>& v) {
            for (int i=0 ; i<dim ; ++i)
                put(v[i]);
        }

        template <class S>
        void put(const Eigen::Quaternion<S>& q) {
            put(q.coeffs());
        }

        void put(const std::string& str) {
            assert(str.size() <= remaining());
            std::copy(str.begin(), str.end(), position_);
            position_ += str.size();
        }

    private:
        template <class T, std::size_t ... I>
        void put(const T& tuple, std::index_sequence<I...>) {
            (put(std::get<I>(tuple)), ...);
        }

    public:
        
        template <class ... T>
        void put(const std::tuple<T...>& tuple) {
            put(tuple, std::index_sequence_for<T...>{});
        }

        BufferView view(std::size_t n) {
            assert(position_ + n <= limit_);
            return { position_, position_ + n };
        }
    };
    
    class Buffer : public BufferView {
        char *base_;
        std::size_t capacity_;
        
    public:
        Buffer()
            : base_{nullptr}
            , capacity_{0}
        {
        }

        explicit Buffer(std::size_t n)
            : BufferView(n)
            , base_(BufferView::begin())
            , capacity_{n}
        {
        }

        Buffer(const Buffer&) = delete;
        Buffer(Buffer&& other)
            : BufferView(std::move(other))
            , base_{std::exchange(other.base_, nullptr)}
            , capacity_{std::exchange(other.capacity_, 0)}
        {
        }

        Buffer(const std::string& str)
            : Buffer(str.size())
        {
            std::copy(str.begin(), str.end(), base_);
        }

        ~Buffer() {
            delete[] base_;
        }

        Buffer& operator = (const Buffer&) = delete;
        Buffer& operator = (Buffer&& other) {
            std::swap(BufferView::position_, other.position_);
            std::swap(BufferView::limit_, other.limit_);
            std::swap(base_, other.base_);
            std::swap(capacity_, other.capacity_);
            return *this;
        }

        Buffer& operator += (int i) {
            position_ += i;
            assert(position_ <= limit_);
            return *this;
        }

        Buffer& flip() {
            limit_ = position_;
            position_ = base_;
            return *this;
        }

        Buffer& compact() {
            // move everything from [pos... lim) to [base...)
            if (position_ != base_)
                std::copy(position_, limit_, base_);
            position_ = base_ + remaining();
            limit_ = base_ + capacity_;
            return *this;
        }

        Buffer& compact(std::size_t needed) {
            if (needed <= capacity_)
                return compact();

            while ((capacity_ *= 2) < needed);
            char *newBuf = new char[capacity_];
            std::copy(position_, limit_, newBuf);
            delete[] base_;
            base_ = newBuf;
            position_ = newBuf + remaining();
            limit_ = newBuf + capacity_;
            return *this;
        }

        operator std::string () const {
            return std::string(begin(), end());
        }
    };
}

#endif
