#pragma once
#ifndef MPL_DEMO_BLENDER_PY_HPP
#define MPL_DEMO_BLENDER_PY_HPP

#include <ostream>

namespace mpl::demo {
    template <class Char, class Traits>
    class BlenderPy {
        std::basic_ostream<Char, Traits>& out_;
        int indentLevel_;

    public:
        class Line {
            std::basic_ostream<Char, Traits>* out_;
            
        public:
            Line(const Line&) = delete;
            Line(Line&& other)
                : out_{std::exchange(other.out_, nullptr)}
            {
            }
            
            template <class T>
            Line(std::basic_ostream<Char, Traits>& out, int indentLevel, T&& arg)
                : out_(&out)
            {
                for (int i=0 ; i<indentLevel ; ++i)
                    out << "    ";
                
                out << std::forward<T>(arg);
            }

            ~Line() {
                if (out_)
                    (*out_) << '\n';
            }

            template <class T>
            Line& operator << (T&& other) {
                (*out_) << std::forward<T>(other);
                return *this;
            }
        };
        
    public:
        BlenderPy(std::basic_ostream<Char, Traits>& out)
            : out_(out)
            , indentLevel_{0}
        {
        }
        
        BlenderPy(std::basic_ostream<Char, Traits>& out, int indentLevel)
            : out_(out)
            , indentLevel_{indentLevel}
        {
        }

        BlenderPy indented() {
            return { out_, indentLevel_ + 1 };
        }

        template <class T>
        Line operator << (T&& arg) {
            return Line(out_, indentLevel_, std::forward<T>(arg));
        }
    };

    template <class Char, class Traits>
    BlenderPy(std::basic_ostream<Char, Traits>&) -> BlenderPy<Char, Traits>;
}


#endif
