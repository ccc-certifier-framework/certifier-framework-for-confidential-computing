#include <aws/lambda-runtime/runtime.h>
#include <aws/core/Aws.h>
#include <aws/core/utils/Outcome.h>
#include <aws/lambda/LambdaClient.h>
#include <aws/lambda/model/InvokeRequest.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <fstream>
#include <iostream>

static const char* ALLOCATION_TAG = "mplLambdaAWS";

static std::shared_ptr<Aws::Lambda::LambdaClient> m_client;

void invokeLambda() {
    Aws::Lambda::Model::InvokeRequest invokeRequest;
    invokeRequest.SetFunctionName("mpl_lambda_aws_test");
    invokeRequest.SetInvocationType(Aws::Lambda::Model::InvocationType::Event);
    std::shared_ptr<Aws::IOStream> payload = Aws::MakeShared<Aws::StringStream>("PayloadData");
    Aws::Utils::Json::JsonValue jsonPayload;
    jsonPayload.WithString("scenario", "se3");
    jsonPayload.WithString("coordinator", "35.165.206.179");
    jsonPayload.WithString("start", "0,0,0,1,270,160,-200");
    jsonPayload.WithString("goal", "0,0,0,1,270,160,-400");
    jsonPayload.WithString("min", "53.46,-21.25,-476.86");
    jsonPayload.WithString("max", "402.96,269.25,-91.0");
    jsonPayload.WithString("algorithm", "rrt");
    jsonPayload.WithString("env", "resources/se3/Twistycool_env.dae");
    jsonPayload.WithString("robot", "resources/se3/Twistycool_robot.dae");
    jsonPayload.WithString("envFrame", "");
    *payload << jsonPayload.View().WriteReadable();
    invokeRequest.SetBody(payload);
    invokeRequest.SetContentType("application/json");

    auto outcome = m_client->Invoke(invokeRequest);
    if (outcome.IsSuccess())
    {
        auto &result = outcome.GetResult();
        Aws::IOStream& payload = result.GetPayload();
        Aws::String functionResult;
        std::getline(payload, functionResult);
        std::cout << "Lambda result:\n" << functionResult << "\n\n";
    }
    else {
        auto &error = outcome.GetError();
        std::cout << "Error: " << error.GetExceptionName() << "\nMessage: " << error.GetMessage() << "\n\n";
    }
}

int main(int argc, char *argv[]) {
    Aws::SDKOptions options;
    Aws::InitAPI(options);
    Aws::Client::ClientConfiguration clientConfig;
    clientConfig.region = "us-west-2";
    m_client = Aws::MakeShared<Aws::Lambda::LambdaClient>(ALLOCATION_TAG, clientConfig);
    invokeLambda();
    Aws::ShutdownAPI(options);
    return 0;
}

