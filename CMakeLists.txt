cmake_minimum_required(VERSION 3.16)

project(wgproxy LANGUAGES C)

add_executable(${PROJECT_NAME}
    "src/wgproxy.c"
)
