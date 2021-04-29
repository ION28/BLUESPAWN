orig_dir=$( pwd )
cd BLUESPAWN-static-lib
compile_lib()
{
    cfiles=$( find ./src/ -name "*.cpp" )
    include="-I./headers"
    g++ -std=c++2a -I./headers -c $cfiles
    if [ $? -ne 0 ];
    then
        echo "Error compiling static library"
        find ./src/ -name "*.o" -delete
        exit 0
    fi
    ofiles=$( find ./src/ -name "*.o" )
    ar rcs libbluespawn.a $ofiles
    find ./src/ -name "*.o" -delete
}

echo "Attempting to compile library"
compile_lib