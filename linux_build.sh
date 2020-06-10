#!/bin/sh

#for now this will do although eventually make a makefile
orig_dir=$( pwd )
cfiles="src/common/StringUtils.cpp"
cfiles="$cfiles src/common/Utils.cpp"
cfiles="$cfiles src/common/DynamicLinker.cpp"
cfiles="$cfiles src/hunt/Hunt.cpp"
cfiles="$cfiles src/hunt/HuntRegister.cpp"
cfiles="$cfiles src/hunt/Scope.cpp"
cfiles="$cfiles src/monitor/EventManager.cpp"
cfiles="$cfiles src/monitor/Event.cpp"
cfiles="$cfiles src/monitor/EventListener.cpp"
cfiles="$cfiles src/monitor/etw/ETW_Wrapper.cpp"
cfiles="$cfiles src/reaction/CarveMemory.cpp"
cfiles="$cfiles src/reaction/QuarantineFile.cpp"
cfiles="$cfiles src/reaction/SuspendProcess.cpp"
cfiles="$cfiles src/reaction/Reaction.cpp"
cfiles="$cfiles src/reaction/ReactLog.cpp"
cfiles="$cfiles src/reaction/DeleteFile.cpp"
cfiles="$cfiles src/user/BLUESPAWN.cpp"
cfiles="$cfiles src/user/CLI.cpp"
cfiles="$cfiles src/user/banners.cpp"
cfiles="$cfiles src/mitigation/Mitigation.cpp"
cfiles="$cfiles src/mitigation/MitigationRegister.cpp"
cfiles="$cfiles src/util/configurations/CollectInfo.cpp"
cfiles="$cfiles src/util/eventlogs/EventLogItem.cpp"
cfiles="$cfiles src/util/eventlogs/EventSubscription.cpp"
cfiles="$cfiles src/util/eventlogs/XpathQuery.cpp"
cfiles="$cfiles src/util/eventlogs/EventLogs.cpp"
cfiles="$cfiles src/util/permissions/permissions.cpp"
cfiles="$cfiles src/util/processes/CheckLolbin.cpp"
cfiles="$cfiles src/util/processes/CommandParser.cpp"
cfiles="$cfiles src/util/processes/Process.cpp"
cfiles="$cfiles src/util/processes/ParseCobalt.cpp"
cfiles="$cfiles src/util/log/CLISink.cpp"
cfiles="$cfiles src/util/log/ServerSink.cpp"
cfiles="$cfiles src/util/log/XMLSink.cpp"
cfiles="$cfiles src/util/log/LogLevel.cpp"
cfiles="$cfiles src/util/log/HuntLogMessage.cpp"
cfiles="$cfiles src/util/log/DebugSink.cpp"
cfiles="$cfiles src/util/filesystem/YaraScanner.cpp"
cfiles="$cfiles src/util/filesystem/FileSystem.cpp"
cfiles="$cfiles ../build/indicators.o ../build/severe.o"
incdirs="-I./headers/ -I./resources/ -I./external/tinyxml2/ -I./external/yara/libyara/include/ -I./external/cxxopts/include/"
libs="-L.$orig_dir/build/tinyxml2.a -L$orig_dir/build/libyara.a"
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
    zip resources/severe.bin resources/severe2.yar resrouces/severe.yar

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
    cd ../..
}

cleanup_stuff()
{
    #cleanup function
    #first cleanup externals
    rm -rf build

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
    g++ -std=c++17 $incdirs $libs $cfiles -o "$orig_dir/build/bluespawn.out"
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