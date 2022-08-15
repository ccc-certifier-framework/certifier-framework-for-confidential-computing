# mplambda
Motion Planning Lambdas

# Requirements
* CMake 3.11+ [https://cmake.org/]
* C++ 17 compiler (GCC 8+ or clang 5+ recommended) 
* nigh [https://github.com/UNC-Robotics/nigh]
* Eigen [http://eigen.tuxfamily.org/index.php?title=Main_Page]
* FCL [https://github.com/flexible-collision-library/fcl] (build from source)
* libccd [https://github.com/danfis/libccd] (build from source)
* assimp [https://github.com/assimp/assimp] (usually available in package systems)
* libatomic (required by some compilers, usually available in package systems)
* (Optional: ninja [https://ninja-build.org/] build tool, usually in package systems)

## Installing Required Software from Package Systems

For requires software that is available in package systems, use the system's package installer or equivalent to install.  Here are a few examples.  Some of these examples are untested, but should be close enough to get one started.  Please update this README with the correct information.

### Ubuntu Linux
```console
% sudo apt install g++ clang++ libeigen libassimp ninja
```

### Macports
```console
% sudo port install g++-9 clang-8.0 eigen3 assimp ninja
```

### Homebrew
```console
% brew install gcc eigen assimp ninja
```

### Amazon Linux
```console
% sudo yum install g++ clang++ assimp ninja
```
## Installing Required Software from Source

Both `libccd` and `fcl` should usually be built from source, as the package versions are often out of date.  FCL requires libccd, so install libccd first.

### libccd

IMPORTANT!  In the instructions below change `g++` and `gcc` to match the compiler you will be using to build this project.  E.g., `CXX=g++-9 CC=gcc-9` or `CXX=clang++-7 CC=clang-7`. 

```console
% git clone https://github.com/danfis/libccd.git
% cd libccd
% mkdir build
% cd build
% CXX=g++ CC=gcc cmake -DCMAKE_BUILD_TYPE=Release ..
% make -j4
% sudo make install
```
### FCL

IMPORTANT!  See note above on compiler setup.
```console
% git clone https://github.com/flexible-collision-library/fcl.git
% cd fcl
% mkdir build
% cd build
% CXX=g++ CC=gcc cmake -DCMAKE_BUILD_TYPE=Release ..
% make -j4
% sudo make install
````

# Setup instructions

First install required software.  Note that `nigh` should be checked out to the same level as this project.  For example, if you have `mplambda` checked out to `~/projects/mplambda`, nigh should be checked out to `~/projects/nigh`

To build:

```console
# change to the checked out directory
$ cd mplambda
$ mkdir -p build/Debug
$ cd build/Debug
```

(Option 1) for ninja builds, run:

```console
$ cmake -DCMAKE_BUILD_TYPE=Debug -G Ninja ../..
$ ninja
```

(Option 2) for make builds, run:

```console
$ cmake -DCMAKE_BUILD_TYPE=Debug ../..
$ make -j4
```

# Troubleshooting

If your C++17 compiler has a different name than the default one used by CMake, you can specify which compiler to use with the `CXX` environment variable, e.g., the following example uses `clang++-mp-7.0` as the CXX compiler.

```console
$ CXX=clang++-mp-7.0 cmake -DCMAKE_BUILD_TYPE=Debug ../..
```

If CMake complains about pkgconfig, then you may have to set the `PKG_CONFIG_PATH` environment variable.  This can be done in the same way as `CXX`.  Typically, this message can be fixed by adding `/usr/local/lib/pkgconfig`.
```console
$ PKG_CONFIG_PATH=/usr/local/lib/pkgconfig cmake -DCMAKE_BUILD_TYPE=Debug ../..
```

To specify both `PKG_CONFIG_PATH` and `CXX`, separate them by a space.

**Homebrew** seems to require use of **gcc**. Specify this compiler when running cmake, as you did when installing libccd and fcl.

```console
$ CC=GCC-9 CXX=g++-9 cmake -DCMAKE_BUILD_TYPE=Debug -G Ninja ../..
```

# Running

First start the Coordinator process in its own terminal window:
```console
$ ./mpl_coordinator
```
It should display a few lines about it listening on a port.

In a *separate* window, run the robot client command with a test problem from OMPL APP:
```console
$ ./mpl_robot --coordinator=localhost --start=0,0,0,1,270,160,-200 --goal=0,0,0,1,270,160,-400 --min=53.46,-21.25,-476.86 --max=402.96,269.25,-91.0 --algorithm=rrt --env Twistycool_env.dae --robot Twistycool_robot.dae 
```

# AWS: Creating and Using the Lambda
Resource: https://aws.amazon.com/blogs/compute/introducing-the-c-lambda-runtime/. This was used to setup the framework (install packages, linking, etc.). We use `PROJECT_NAME` of `mpl_lambda_aws` for this README. Instructions for the trust policy are below. Below will pickup once `mpl_lambda_aws.zip` exists.

**Trust Policy**

While this is found at the resource, stating the method we used.

Within your build directory, ensure `trust-policy.json ` exists. If it does not, create the following JSON file for the trust policy and name it `trust-policy.json`.
```code
{
 "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": ["lambda.amazonaws.com"]
      },
      "Action": "sts:AssumeRole"
    }
  ] 
}
```
Now, from the build directory, run:
```console
$ aws iam create-role \
--role-name lambda-cpp-demo \
--assume-role-policy-document file://trust-policy.json
```

This should output JSON that contains the newly created IAM role information. Make sure to note down the “Arn” value from that JSON. You need it later. The Arn looks like the following:
```code
“Arn”: “arn:aws:iam::<account_id>:role/lambda-cpp-demo”
```

**The Lambda Function**

To **generat the zip file**, after building and making, call
```console
$ make mpl_lambda_aws_zip
```
within the build directory. This will generate the zip and add the needed resource files. 


To initially **create** the Lambda, run:

```console
$ aws lambda create-function \
--function-name mpl_lambda_aws_test \
--role arn:aws:iam::788532905224:role/mplambda_test \
--runtime provided \
--timeout 60 \
--memory-size 256 \
--handler mpl_lambda_aws \
--zip-file fileb://mpl_lambda_aws.zip
```

To **update** the Lambda, run:
```console
$ aws lambda update-function-code --function-name mpl_lambda_aws_test --zip-file fileb://mpl_lambda_aws.zip
```

To **invoke** a test run of the Lambda, run:
```console
$ ./mpl_lambda_invoke
```
This is a hardcoded example for testing.

To **invoke** the Lambda with your own parameters, replace relevant data and run:

```console
$ aws lambda invoke --function-name mpl_lambda_aws_test --payload '{"scenario":"se3", "coordinator":"35.165.206.179", "start":"0,0,0,1,270,160,-200", "goal":"0,0,0,1,270,160,-400", "min":"53.46,-21.25,-476.86", "max":"402.96,269.25,-91.0", "algorithm":"rrt", "env":"resources/se3/Twistycool_env.dae", "robot":"resources/se3/Twistycool_robot.dae", "envFrame":""}' output.txt
```


