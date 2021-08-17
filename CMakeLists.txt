cmake_minimum_required(VERSION 3.7)

project(trace_target_func_usage)

add_definitions(-DSHOW_RESULTS)

if (NOT DEFINED DynamoRIO_DIR)
  set(DynamoRIO_DIR "${PROJECT_SOURCE_DIR}/../cmake" CACHE PATH
    "DynamoRIO installation's cmake directory")
endif (NOT DEFINED DynamoRIO_DIR)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

function (add_sample_client name source_file_list extension_list)
  add_library(${name} SHARED ${source_file_list})
  configure_DynamoRIO_client(${name})
  foreach (ext ${extension_list})
    use_DynamoRIO_extension(${name} ${ext})
  endforeach (ext)
endfunction (add_sample_client)

add_sample_client(trace_target_func_usage "trace_target_func_usage.c;utils.c;memtrace.c" "drmgr;drreg;drutil;drx;drwrap;drsyms")
