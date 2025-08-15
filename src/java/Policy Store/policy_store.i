%module policy_store

%{
#include "certifier.h"
using namespace certifier::framework;
%}

%include "std_string.i"

namespace certifier {
  namespace framework {
    class policy_store {
    public:
      policy_store();
      policy_store(unsigned max_ents);
      ~policy_store();

      unsigned get_num_entries();
      bool add_entry(const std::string& tag, const std::string& type, const std::string& value);
      int find_entry(const std::string& tag, const std::string& type);
      bool get(unsigned ent, std::string* v);
      bool put(unsigned ent, const std::string v);
    };
  }
}
