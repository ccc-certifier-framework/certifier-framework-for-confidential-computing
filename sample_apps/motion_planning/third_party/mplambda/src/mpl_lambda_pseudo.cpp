#include <mpl/demo/lambda_common.hpp>
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "src/proto/hello.pb.h"
#include <iostream>

namespace asylo {

    class mplambda : public asylo::TrustedApplication {
        

        public:
        asylo::Status Run(const asylo::EnclaveInput &input,
                          asylo::EnclaveOutput *output) override {

                hello_world::MP_Lambda_Input lambda_input = input.GetExtension(hello_world::lambda_input);
                static const std::string resourceDirectory = "mplambda/resources/se3/";

                mpl::demo::AppOptions options(lambda_input);

                if (!options.env_.empty())
                    options.env_ = resourceDirectory + options.env_;
                if (!options.robot_.empty())
                    options.robot_ = resourceDirectory + options.robot_;

                mpl::demo::runSelectPlanner(options);

                return asylo::Status::OkStatus();
        }

    };

    TrustedApplication *BuildTrustedApplication() { return new mplambda; }

}
