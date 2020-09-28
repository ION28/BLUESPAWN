#!/bin/sh

#for now this will do although eventually make a makefile
orig_dir=$( pwd )
cd BLUESPAWN-unix-client
cfiles="$( find ./src/ -name "*.cpp" )"
cd ..
cfiles="$cfiles ../build/indicators.o ../build/severe.o ../build/libyara.a ../build/libtinyxml2.a"
incdirs="-I./headers/ -I./resources/ -I./external/tinyxml2/ -I./external/yara/libyara/include/ -I./external/cxxopts/include/"

install_depends()
{
    apt-get install make automake libtool gcc
    apt-get install flex bison
    apt-get install libssl-dev
    apt-get install libzip-dev
}

create_resources()
{
    cd BLUESPAWN-unix-client
    zip resources/indicators.bin resources/indicators.yar
    zip resources/severe.bin resources/severe2.yar resources/severe.yar

    objcopy -I binary -O elf64-x86-64 resources/indicators.bin resources/indicators.o
    objcopy -I binary -O elf64-x86-64 resources/severe.bin resources/severe.o

    mv resources/indicators.o $orig_dir/build/indicators.o
    mv resources/severe.o $orig_dir/build/severe.o
    rm resources/indicators.bin
    rm resources/severe.bin
    cd ..
}

compile_external()
{
    cd BLUESPAWN-unix-client
    cd external/tinyxml2
    #now make tinyxml
    make distclean
    make staticlib
    cd ..
    cp tinyxml2/libtinyxml2.a $orig_dir/build/libtinyxml2.a
    #now yara
    cd yara
    ./bootstrap.sh
    ./configure --enable-static
    make
    cp libyara/.libs/libyara.a $orig_dir/build/libyara.a
    cd ../../..
}

cleanup_stuff()
{
    #cleanup function
    #first cleanup externals
    rm -rf build
    if [ -f "a.out" ];
    then
        rm a.out
    fi

    cd BLUESPAWN-unix-client
    cd external/tinyxml2
    make clean
    make distclean
    cd ..
    cd yara
    make clean
    make distclean
    cd ../..
    find . -type f -name "*.o" -delete
    cd ..
}

compile_actual()
{
    cd BLUESPAWN-unix-client
    g++ -std=c++2a $incdirs $cfiles -o "$orig_dir/build/bluespawn.out" -lcrypto -lpthread
    cd ..  
}



if [ "$1" = "clean" ];
then
    echo "Cleaning up build related files"
    cleanup_stuff
else
    echo "Attempting to compile"
    rm -rf build && mkdir build
    create_resources
    compile_external
    compile_actual
fi;
