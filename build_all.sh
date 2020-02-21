#!bin/bash

[ -d build ] || mkdir build
cd build
cmake -G "Unix Makefiles" -D CMAKE_CXX_COMPILER=g++ -D CMAKE_C_COMPILER=gcc ..
make  
cd ..