cmake_minimum_required(VERSION 3.5)
project(JSScanner)

option(TEST "Build for the test environment" OFF)



if(TEST)
    # 테스트 환경 (TEST=ON)
   
   set(CMAKE_CXX_STANDARD 20)
   set(CMAKE_CXX_STANDARD_REQUIRED ON)

   file(GLOB_RECURSE SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
)
   list(FILTER SOURCES EXCLUDE REGEX ".*/CMakeFiles/.*")

   list(APPEND SOURCES ${LINUX_MAC_SOURCES})
	
   add_executable(${PROJECT_NAME} ${SOURCES})
   set(CPPCORE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../../../cppcore)
   set(EXTERNAL_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mon47-opensrc/opensrc)

   target_include_directories(${PROJECT_NAME} PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}
                ${CMAKE_CURRENT_SOURCE_DIR}/../Inc
		${CPPCORE_ROOT}/Inc
		${EXTERNAL_LIB}/libpqxx/include
		${EXTERNAL_LIB}/curl/include
		${EXTERNAL_LIB}/ada-url/include
		${EXTERNAL_LIB}/lz4/include
		${EXTERNAL_LIB}/openssl/include
		${EXTERNAL_LIB}/libpq/include
		${EXTERNAL_LIB}/zlib/include
		${EXTERNAL_LIB}/c-ares/include
		${EXTERNAL_LIB}/libpsl/include
		${EXTERNAL_LIB}/icu/include
		${EXTERNAL_LIB}/libunistring/include
		${EXTERNAL_LIB}/gumbo/include
		${EXTERNAL_LIB}/quickjs-ng/include
		${EXTERNAL_LIB}/re2/include
		${EXTERNAL_LIB}/abseil/include
	)
   set(MON47_LINUX_LINK_LIBS
			"${EXTERNAL_LIB}/libpqxx/lib/libpqxx.so"
			"${EXTERNAL_LIB}/libpq/lib/libpq.so"
			"${EXTERNAL_LIB}/libpq/lib/libpgtypes.so"
			"${EXTERNAL_LIB}/libpq/lib/libecpg.so"
			"${EXTERNAL_LIB}/libpq/lib/libecpg_compat.so"
			"${EXTERNAL_LIB}/curl/lib/libcurl.so"
			"${EXTERNAL_LIB}/openssl/lib/libssl.so"
			"${EXTERNAL_LIB}/openssl/lib/libcrypto.so"
			"${EXTERNAL_LIB}/ada-url/lib/libada.so"
			"${EXTERNAL_LIB}/c-ares/lib/libcares.so"
			"${EXTERNAL_LIB}/zlib/lib/libz.so"
			"${EXTERNAL_LIB}/libidn2/lib/libidn2.so"
			"${EXTERNAL_LIB}/icu/lib/libicudata.so"
			"${EXTERNAL_LIB}/icu/lib/libicui18n.so"
			"${EXTERNAL_LIB}/icu/lib/libicuio.so"
			"${EXTERNAL_LIB}/icu/lib/libicuuc.so"
			"${EXTERNAL_LIB}/libpsl/lib/libpsl.so"
			"${EXTERNAL_LIB}/libunistring/lib/libunistring.so"
			"${EXTERNAL_LIB}/quickjs-ng/lib/libqjs.so"
		)

		if(EXISTS "${EXTERNAL_LIB}/gumbo/lib/libgumbo.so")
			list(APPEND MON47_LINUX_LINK_LIBS "${EXTERNAL_LIB}/gumbo/lib/libgumbo.so")
		else()
			list(APPEND MON47_LINUX_LINK_LIBS "${EXTERNAL_LIB}/gumbo/lib/libgumbo.a")
		endif()

		# RE2 library
		if(EXISTS "${EXTERNAL_LIB}/re2/lib/libre2.so")
			list(APPEND MON47_LINUX_LINK_LIBS "${EXTERNAL_LIB}/re2/lib/libre2.so")
		elseif(EXISTS "${EXTERNAL_LIB}/re2/lib/libre2.a")
			list(APPEND MON47_LINUX_LINK_LIBS "${EXTERNAL_LIB}/re2/lib/libre2.a")
		endif()

		target_link_libraries(${PROJECT_NAME} PRIVATE
			${CPPCORE_ROOT}/Build/LinuxRelease/libcppcore.a
			${CMAKE_CURRENT_SOURCE_DIR}/../../../InternalLib/LinuxRelease/libDBCore.a
		        #${CMAKE_CURRENT_SOURCE_DIR}/../../../InternalLib/LinuxRelease/libResolver.a
			${CMAKE_CURRENT_SOURCE_DIR}/../../../InternalLib/LinuxRelease/libProxy.a
			${MON47_LINUX_LINK_LIBS}
			dl
			pthread
		)
		
		target_compile_options(${PROJECT_NAME} PUBLIC -O3 -fPIC)

else()
    # 배포 환경 (TEST=OFF)

   include(${CMAKE_SOURCE_DIR}/cmake/Mon47Common.cmake)
   message(STATUS "Configuring for DEPLOYMENT environment")
   setup_mon47_project("SHARED_LIBRARY")

   target_include_directories(${PROJECT_NAME} PRIVATE
       ${CMAKE_CURRENT_SOURCE_DIR}
       ${CMAKE_CURRENT_SOURCE_DIR}/../Inc
   )

   target_link_libraries(${PROJECT_NAME} PRIVATE
   )
endif()