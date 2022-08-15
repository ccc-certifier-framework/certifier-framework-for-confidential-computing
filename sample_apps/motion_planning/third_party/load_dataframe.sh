echo "Git Cloning the DataFrame Repo..."
git clone git@github.com:hosseinmoein/DataFrame.git
cd DataFrame
git checkout 29695d124dbd7074ffbf73ad8f94f3178e0ca26e

echo "Applying patch"
git apply ../DataFrame.patch

echo "Compiling binary"
mkdir build
cd build 
cmake .. && make 
