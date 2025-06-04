cmake_minimum_required(VERSION 3.12.4)

project(Wazuh)

set(ENGINE_DEPS_INSTALL_DIR ${CMAKE_SOURCE_DIR}/deps/build)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
  if(CMAKE_SYMBOLS_IN_RELEASE MATCHES "ON")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  else()
    set(CMAKE_BUILD_TYPE Release)
  endif()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/ ABSOLUTE)

################################
# External dependencies
################################

function(check_and_download_dep libname url)
    if(NOT EXISTS ${SRC_FOLDER}/external/${libname})
        message("==============================================")

        # Download library from S3 bucket
        message("Downloading ${libname}...")
        file(DOWNLOAD ${url}/${libname}.tar.gz ${SRC_FOLDER}/external/${libname}.tar.gz
                TIMEOUT 60  # seconds
                STATUS DOWNLOAD_STATUS)
        list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
        list(GET DOWNLOAD_STATUS 1 STATUS_MESSAGE)
        if(NOT STATUS_CODE EQUAL 0)
            message(FATAL_ERROR "Error downloading ${libname}: ${STATUS_MESSAGE} (${STATUS_CODE}).")
        endif(NOT STATUS_CODE EQUAL 0)

        # Extract library
        message("Extracting ${libname}.tar.gz")
        execute_process(COMMAND ${CMAKE_COMMAND} -E tar xfz "${SRC_FOLDER}/external/${libname}.tar.gz" WORKING_DIRECTORY ${SRC_FOLDER}/external RESULT_VARIABLE STATUS_VALUE)
        if(NOT STATUS_VALUE EQUAL 0)
            message(FATAL_ERROR "Error extracting ${libname}: ${STATUS_VALUE}.")
        endif(NOT STATUS_VALUE EQUAL 0)

        # Cleanup tar file
        message("Cleaning ${libname}.tar.gz")
        file(REMOVE ${SRC_FOLDER}/external/${libname}.tar.gz)
    endif()
endfunction(check_and_download_dep)

set(EXTERNAL_RES
    nlohmann
    googletest
    benchmark
    cpp-httplib
    )

if(NOT EXTERNAL_DEPS_VERSION)
    set(EXTERNAL_DEPS_VERSION "21")
endif(NOT EXTERNAL_DEPS_VERSION)

if(NOT RESOURCES_URL)
    set(RESOURCES_URL "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/sources")
endif(NOT RESOURCES_URL)

if(NOT PRECOMPILED_RESOURCES_URL)
    set(PRECOMPILED_RESOURCES_URL "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/linux/amd64")
endif(NOT PRECOMPILED_RESOURCES_URL)

# Download external libraries
foreach(loop_var ${EXTERNAL_RES})
    check_and_download_dep(${loop_var} ${RESOURCES_URL})
endforeach(loop_var)

# Read the VERSION JSON file
file(READ "${SRC_FOLDER}/../VERSION.json" VERSION_JSON)

# Extract "version"
string(REGEX MATCH "\"version\"[ \t]*:[ \t]*\"([^\"]+)\"" _ ${VERSION_JSON})
set(VERSION_FILE "v${CMAKE_MATCH_1}")  # <-- Add "v" prefix since old VERSION file had it

# Extract "stage" as revision
string(REGEX MATCH "\"stage\"[ \t]*:[ \t]*\"([^\"]+)\"" _ ${VERSION_JSON})
set(REVISION_FILE "${CMAKE_MATCH_1}")

# Define preprocessor macros
add_definitions(-DVERSION="${VERSION_FILE}")
add_definitions(-DREVISION="${REVISION_FILE}")

## If REVISION OR FILE is empty fail
if("${REVISION_FILE}" STREQUAL "")
    message(FATAL_ERROR "REVISION file is empty")
endif("${REVISION_FILE}" STREQUAL "")

if("${VERSION_FILE}" STREQUAL "")
    message(FATAL_ERROR "VERSION file is empty")
endif("${VERSION_FILE}" STREQUAL "")

message("==============================================")
message("Wazuh version: ${VERSION_FILE}")
message("Wazuh revision: ${REVISION_FILE}")
message("==============================================")

set(BENCHMARK_ENABLE_TESTING "OFF")
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/rocksdb/build/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/lzma/build/)
link_directories(${SRC_FOLDER}/external/zlib/)
link_directories(${SRC_FOLDER}/external/zlib/contrib/minizip/)
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)

include_directories(${SRC_FOLDER}/shared_modules/common)
include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/router/include)
include_directories(${SRC_FOLDER}/shared_modules/content_manager/include)
include_directories(${SRC_FOLDER}/shared_modules/indexer_connector/include)
include_directories(${SRC_FOLDER}/shared_modules/http-request/include)
include_directories(${SRC_FOLDER}/shared_modules/keystore/include)
include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/googletest/googletest/include)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/lzma/src/liblzma/api)
include_directories(${SRC_FOLDER}/external/zlib/)
include_directories(${SRC_FOLDER}/external/zlib/contrib/)
include_directories(${SRC_FOLDER}/external/libarchive/libarchive/)

# Engine dependencies
include_directories(${ENGINE_DEPS_INSTALL_DIR}/openssl/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/openssl/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/protobuf/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/protobuf/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/fmt/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/fmt/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/spdlog/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/spdlog/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/date/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/date/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/fast-float/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/fast-float/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/rapidjson/include)
# rapidjson is header-only via CMake install, but might create a lib dir for cmake files
include_directories(${ENGINE_DEPS_INSTALL_DIR}/pugixml/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/pugixml/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/yaml-cpp/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/yaml-cpp/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/re2/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/re2/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/curl/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/curl/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/libmaxminddb/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/libmaxminddb/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/concurrentqueue/include)
# concurrentqueue is header-only
include_directories(${ENGINE_DEPS_INSTALL_DIR}/rxcpp/include)
# rxcpp is header-only
include_directories(${ENGINE_DEPS_INSTALL_DIR}/taskflow/include)
# taskflow is header-only
include_directories(${ENGINE_DEPS_INSTALL_DIR}/rocksdb/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/rocksdb/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/opentelemetry-cpp/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/opentelemetry-cpp/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/cpp-httplib/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/cpp-httplib/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/gtest/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/gtest/lib)
include_directories(${ENGINE_DEPS_INSTALL_DIR}/benchmark/include)
link_directories(${ENGINE_DEPS_INSTALL_DIR}/benchmark/lib)

add_subdirectory(shared_modules/utils)
add_subdirectory(shared_modules/router)
add_subdirectory(shared_modules/content_manager)

set(CURL_DEP wazuhext)
add_subdirectory(shared_modules/http-request)
add_subdirectory(shared_modules/indexer_connector)
add_subdirectory(wazuh_modules/vulnerability_scanner)
add_subdirectory(shared_modules/keystore)
add_subdirectory(wazuh_modules/inventory_harvester)

# Add engine
add_subdirectory(engine)
