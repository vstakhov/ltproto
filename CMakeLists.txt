PROJECT(ltproto C)

SET(LTPROTO_VERSION_MAJOR 0)
SET(LTPROTO_VERSION_MINOR 0)
SET(LTPROTO_VERSION_PATCH 1)


SET(LTPROTO_VERSION         "${LTPROTO_VERSION_MAJOR}.${LTPROTO_VERSION_MINOR}.${LTPROTO_VERSION_PATCH}")

CMAKE_MINIMUM_REQUIRED(VERSION 2.6.0 FATAL_ERROR)

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckLibraryExists)
INCLUDE(CheckCCompilerFlag)
INCLUDE(FindOpenSSL)
INCLUDE(CheckCSourceRuns)

OPTION(ENABLE_DEBUG_MODE   "Enable debug output [default: ON]"                  ON)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: OFF]"                 OFF)
OPTION(ENABLE_THREAD_UNSAFE "Enable thread unsafe build [default: OFF]"         OFF)
OPTION(ENABLE_GPERF_TOOLS  "Enable google perftools [default: OFF]"             OFF)

# List of available modules in compile time
MACRO(AddModules MLIST)
	# Generate unique string for this build
    STRING(RANDOM LENGTH 8 _MODULES_ID)
    SET(MODULES_ID ${_MODULES_ID} CACHE INTERNAL "Modules ID" FORCE)
    FILE(WRITE "${CMAKE_BINARY_DIR}/src/modules.c" "/* ${MODULES_ID} */\n#include \"config.h\"\n")
    FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "#include \"ltproto_internal.h\"\n")
    # Handle even old cmake
    LIST(LENGTH ${MLIST} MLIST_COUNT)
    MATH(EXPR MLIST_MAX ${MLIST_COUNT}-1)
    
    FOREACH(MOD_IDX RANGE ${MLIST_MAX})
        LIST(GET ${MLIST} ${MOD_IDX} MOD)
        FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "extern module_t ${MOD}_module;\n")
    ENDFOREACH(MOD_IDX RANGE ${MLIST_MAX})
         
    FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "\n\nmodule_t *modules[] = {\n")
    
    FOREACH(MOD_IDX RANGE ${MLIST_MAX})
        LIST(GET ${MLIST} ${MOD_IDX} MOD)
        FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "&${MOD}_module,\n")
    ENDFOREACH(MOD_IDX RANGE ${MLIST_MAX})
    
    FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "NULL\n};\n")
    
ENDMACRO(AddModules MLIST)

MACRO(AddAllocators ALIST)
# Handle even old cmake
    LIST(LENGTH ${ALIST} ALIST_COUNT)
    MATH(EXPR ALIST_MAX ${ALIST_COUNT}-1)
    
    FOREACH(AL_IDX RANGE ${ALIST_MAX})
        LIST(GET ${ALIST} ${AL_IDX} ALLOC)
        FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "extern allocator_t ${ALLOC}_allocator;\n")
    ENDFOREACH(AL_IDX RANGE ${ALIST_MAX})
         
    FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "\n\nallocator_t *allocators[] = {\n")
    
    FOREACH(AL_IDX RANGE ${ALIST_MAX})
        LIST(GET ${ALIST} ${AL_IDX} ALLOC)
        FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "&${ALLOC}_allocator,\n")
    ENDFOREACH(AL_IDX RANGE ${ALIST_MAX})
    
    FILE(APPEND "${CMAKE_BINARY_DIR}/src/modules.c" "NULL\n};\n")
ENDMACRO(AddAllocators ALIST)

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DLINUX")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_POSIX_C_SOURCE=199506L")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")

IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DBSD")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")

# Process with warn flags
SET(CMAKE_C_WARN_FLAGS "")
CHECK_C_COMPILER_FLAG(-Wall SUPPORT_WALL)
CHECK_C_COMPILER_FLAG(-W SUPPORT_W)
CHECK_C_COMPILER_FLAG(-Wpointer-arith SUPPORT_WPOINTER)
CHECK_C_COMPILER_FLAG(-Wno-unused-parameter SUPPORT_WPARAM)
CHECK_C_COMPILER_FLAG(-Wno-unused-function SUPPORT_WFUNCTION)
CHECK_C_COMPILER_FLAG(-Wunused-variable SUPPORT_WUNUSED_VAR)
CHECK_C_COMPILER_FLAG(-Wno-pointer-sign SUPPORT_WPOINTER_SIGN)
CHECK_C_COMPILER_FLAG(-Wstrict-prototypes SUPPORT_WSTRICT_PROTOTYPES)
CHECK_C_COMPILER_FLAG(-pedantic SUPPORT_PEDANTIC_FLAG)
CHECK_C_COMPILER_FLAG("-std=c99" SUPPORT_STD_FLAG)
IF(SUPPORT_W)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -W")
ENDIF(SUPPORT_W)
IF(SUPPORT_WALL)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wall")
ENDIF(SUPPORT_WALL)
IF(SUPPORT_WPOINTER)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wpointer-arith")
ENDIF(SUPPORT_WPOINTER)
IF(SUPPORT_WPARAM)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-parameter")
ENDIF(SUPPORT_WPARAM)
IF(SUPPORT_WFUNCTION)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-function")
ENDIF(SUPPORT_WFUNCTION)
IF(SUPPORT_WUNUSED_VAR)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wunused-variable")
ENDIF(SUPPORT_WUNUSED_VAR)
IF(SUPPORT_WPOINTER_SIGN)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-pointer-sign")
ENDIF(SUPPORT_WPOINTER_SIGN)
IF(SUPPORT_WSTRICT_PROTOTYPES)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wstrict-prototypes")
ENDIF(SUPPORT_WSTRICT_PROTOTYPES)
IF(SUPPORT_PEDANTIC_FLAG)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -pedantic")
ENDIF(SUPPORT_PEDANTIC_FLAG)
IF(SUPPORT_STD_FLAG)
    SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -std=c99")
ENDIF(SUPPORT_STD_FLAG)
 
CHECK_C_COMPILER_FLAG(-fPIC SUPPORT_FPIC)
IF(SUPPORT_FPIC)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
ENDIF(SUPPORT_FPIC)
CHECK_C_COMPILER_FLAG(-fpic SUPPORT_Fpic)
IF(SUPPORT_Fpic)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fpic")
ENDIF(SUPPORT_Fpic)

IF(OPENSSL_FOUND)
	INCLUDE_DIRECTORIES(OPENSSL_INCLUDE_DIR)
	SET(HAVE_OPENSSL 1)
ENDIF(OPENSSL_FOUND)
 
 # Optimization flags
IF(NOT CMAKE_C_OPT_FLAGS)
    IF(ENABLE_OPTIMIZATION MATCHES "ON")
        SET(CMAKE_C_OPT_FLAGS "-O3 -march=native -fstrict-aliasing")
    ELSE(ENABLE_OPTIMIZATION MATCHES "ON")
        SET(CMAKE_C_OPT_FLAGS "-O0 -fstrict-aliasing -g")
    ENDIF(ENABLE_OPTIMIZATION MATCHES "ON")
ENDIF(NOT CMAKE_C_OPT_FLAGS)

IF(ENABLE_DEBUG_MODE MATCHES "ON")
	SET(CMAKE_C_DEBUG_FLAGS "-g")
ELSE(ENABLE_DEBUG_MODE MATCHES "ON")
	SET(CMAKE_C_DEBUG_FLAGS "")
ENDIF(ENABLE_DEBUG_MODE MATCHES "ON")

SET(CMAKE_C_FLAGS "${CMAKE_C_DEBUG_FLAGS} ${CMAKE_C_OPT_FLAGS} ${CMAKE_C_FLAGS} ${CMAKE_C_WARN_FLAGS}")

FIND_LIBRARY(HAVE_LIBRT rt)

IF(HAVE_LIBRT)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES rt)
ENDIF(HAVE_LIBRT)

# Google performance tools

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	FIND_PATH(GPERF_INCLUDE google/profiler.h PATHS /opt/include
													/usr/include
													/usr/local/include
											  DOC "Path where google perftools includes can be found")
	INCLUDE_DIRECTORIES("${GPERF_INCLUDE}")
	FIND_LIBRARY(GPERF_LIBRARY NAMES profiler PATH_SUFFIXES lib64 lib
                  PATHS
                      ~/Library/Frameworks
                      /Library/Frameworks
                      /usr/local
                      /usr
                      /sw
                      /opt/local
                      /opt/csw
                      /opt
					DOC "Path where the gperf library can be found")
	IF(NOT GPERF_LIBRARY)
		MESSAGE(FATAL_ERROR "gperf tools support is enabled but not found in system")
	ENDIF(NOT GPERF_LIBRARY)
	GET_FILENAME_COMPONENT(GPERF_PATH "${GPERF_LIBRARY}" PATH)
	LINK_DIRECTORIES("${GPERF_PATH}")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
	SET(WITH_GPERF_TOOLS 1)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")
 
# Check platform specific includes
CHECK_INCLUDE_FILES(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES(sys/param.h HAVE_SYS_PARAM_H)
CHECK_INCLUDE_FILES(sys/time.h  HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES("sys/types.h;sys/socket.h;sys/uio.h"   HAVE_SYS_UIO_H)

CHECK_INCLUDE_FILES(fcntl.h     HAVE_FCNTL_H)
CHECK_INCLUDE_FILES(math.h      HAVE_MATH_H)
CHECK_INCLUDE_FILES(stdio.h     HAVE_STDIO_H)
CHECK_INCLUDE_FILES(stdlib.h    HAVE_STDLIB_H)
CHECK_INCLUDE_FILES(string.h    HAVE_STRING_H)
CHECK_INCLUDE_FILES(strings.h   HAVE_STRINGS_H)
CHECK_INCLUDE_FILES(time.h      HAVE_TIME_H)
CHECK_INCLUDE_FILES(unistd.h    HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(sysexits.h  HAVE_SYSEXITS_H)
CHECK_INCLUDE_FILES(stdint.h  HAVE_STDINT_H)
CHECK_INCLUDE_FILES(inttypes.h  HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES(endian.h  HAVE_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/endian.h  HAVE_SYS_ENDIAN_H)
CHECK_INCLUDE_FILES(machine/endian.h  HAVE_MACHINE_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/queue.h  HAVE_SYS_QUEUE_H)
CHECK_INCLUDE_FILES(sys/socket.h  HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES(sys/mman.h  HAVE_SYS_MMAN_H)
CHECK_INCLUDE_FILES(sys/un.h  HAVE_SYS_UN_H)
CHECK_INCLUDE_FILES(sys/stat.h  HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES(sys/wait.h  HAVE_SYS_WAIT_H)
CHECK_INCLUDE_FILES(sys/param.h  HAVE_SYS_PARAM_H)
CHECK_INCLUDE_FILES(sys/cdefs.h  HAVE_SYS_CDEFS_H)
CHECK_INCLUDE_FILES(sys/file.h  HAVE_SYS_FILE_H)
CHECK_INCLUDE_FILES(sys/utsname.h  HAVE_SYS_UTSNAME_H)
CHECK_INCLUDE_FILES(sys/resource.h  HAVE_SYS_RESOURCE_H)
CHECK_INCLUDE_FILES(sys/random.h  HAVE_SYS_RANDOM_H)
CHECK_INCLUDE_FILES("sys/types.h;sys/socket.h;netinet/in.h"  HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES("sys/types.h;sys/socket.h;arpa/inet.h"  HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES("sys/types.h;sys/socket.h;netinet/tcp.h"  HAVE_NETINET_TCP_H)
CHECK_INCLUDE_FILES(poll.h HAVE_POLL_H)
CHECK_INCLUDE_FILES(sys/sendfile.h HAVE_SYS_SENDFILE_H)
CHECK_INCLUDE_FILES(sched.h HAVE_SCHED_H)
CHECK_INCLUDE_FILES("sys/param.h;sys/cpuset.h" HAVE_SYS_CPUSET_H)

IF(HAVE_SCHED_H)
	CHECK_SYMBOL_EXISTS(sched_setaffinity sched.h HAVE_SCHED_SETAFFINITY)
ENDIF(HAVE_SCHED_H)  

IF(HAVE_SYS_CPUSET_H)
	CHECK_SYMBOL_EXISTS(cpuset_setaffinity "sys/param.h;sys/cpuset.h" HAVE_CPUSET_SETAFFINITY)
ENDIF(HAVE_SYS_CPUSET_H)

CHECK_C_SOURCE_RUNS("
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char **argv) {
	if (socket(AF_UNIX, SOCK_SEQPACKET, 0) == -1) {
		return -1;
	}
	return 0;
}
" HAVE_UNIX_SEQPACKET)

CHECK_C_SOURCE_RUNS("
int main(int argc, char **argv) {
	int a = 0;
	if (__sync_bool_compare_and_swap(&a, 0, 1)) {
		return 0;
	}
	return -1;
}
" HAVE_ATOMIC_BUILTINS)

IF(NOT HAVE_ATOMIC_BUILTINS)
	MESSAGE(FATAL_ERROR "Atomic builtins are unsupported in compiler, cannot continue")
ENDIF(NOT HAVE_ATOMIC_BUILTINS)

CHECK_C_SOURCE_RUNS("
int main(int argc, char **argv) {
	int a = 0;
	__asm __volatile(\"monitor\"
	    :  \"=m\" (*(char *)&a)
	    : \"a\" (&a), \"c\" (0), \"d\" (0));
	return 0;
}
" HAVE_MONITOR_MWAIT)

CHECK_C_SOURCE_RUNS("
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
int main(int argc, char **argv) {
	int a = 0;
	struct timeval tv = {.tv_sec = 0, .tv_usec = 100};
	
	if (syscall(SYS_futex, &a, FUTEX_WAIT, 0, &tv, NULL, 0) == -1 && errno != ETIMEDOUT) {
		return -1;
	}
	
	return 0;
}
" HAVE_FUTEX)

CHECK_C_SOURCE_RUNS("
#include <errno.h>
#include <sys/types.h>
#include <sys/umtx.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
	int a = 0;
	struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000};
	
	if (_umtx_op((void *)&a, UMTX_OP_WAIT_UINT, 0, 0, (void *)&ts)== -1 && errno != ETIMEDOUT) {
		return -1;
	}
	
	return 0;
}
" HAVE_UMTX_OP)

IF(NOT HAVE_MONITOR_MWAIT AND NOT HAVE_FUTEX AND NOT HAVE_UMTX_OP)
	MESSAGE(FATAL_ERROR "No spinning logic available, cannot continue (futexes and monitor/mwait are supported now)")
ENDIF(NOT HAVE_MONITOR_MWAIT AND NOT HAVE_FUTEX AND NOT HAVE_UMTX_OP)

# Some dependencies
IF(HAVE_SYS_WAIT_H)
    LIST(APPEND CMAKE_REQUIRED_INCLUDES sys/wait.h)
ENDIF(HAVE_SYS_WAIT_H)
IF(HAVE_TIME_H)
CONFIGURE_FILE(config.h.in src/config.h)
    LIST(APPEND CMAKE_REQUIRED_INCLUDES time.h)
ENDIF(HAVE_TIME_H)
IF(HAVE_SYS_TIME_H)
    LIST(APPEND CMAKE_REQUIRED_INCLUDES sys/time.h)
ENDIF(HAVE_SYS_TIME_H)

CHECK_SYMBOL_EXISTS(clock_gettime time.h HAVE_CLOCK_GETTIME)
IF(HAVE_CLOCK_GETTIME)
    CHECK_SYMBOL_EXISTS(CLOCK_MONOTONIC_RAW time.h HAVE_CLOCK_MONOTONIC_RAW)
    CHECK_SYMBOL_EXISTS(CLOCK_REALTIME_PRECISE time.h HAVE_CLOCK_REALTIME_PRECISE)
ELSE(HAVE_CLOCK_GETTIME)
    CHECK_INCLUDE_FILES(sys/timeb.h HAVE_SYS_TIMEB_H)
ENDIF(HAVE_CLOCK_GETTIME)

IF(HAVE_SCHED_H)
	CHECK_SYMBOL_EXISTS(sched_setaffinity sched.h HAVE_SCHED_SETAFFINITY)
ENDIF(HAVE_SCHED_H)

CHECK_SYMBOL_EXISTS(srandom_r stdlib.h HAVE_SRANDOM_R)
IF(HAVE_SYS_RANDOM_H)
	CHECK_SYMBOL_EXISTS(arc4random stdlib.h;sys/random.h HAVE_ARC4RAND)
ELSE(HAVE_SYS_RANDOM_H)
	CHECK_SYMBOL_EXISTS(arc4random stdlib.h HAVE_ARC4RAND)
ENDIF(HAVE_SYS_RANDOM_H)
CHECK_SYMBOL_EXISTS(MAP_HUGETLB sys/mman.h HAVE_HUGETLB)

IF(ENABLE_THREAD_UNSAFE MATCHES "ON")
	SET(THREAD_UNSAFE 1)
ELSE(ENABLE_THREAD_UNSAFE MATCHES "ON")
	INCLUDE(FindThreads)
	SET(CMAKE_THREAD_PREFER_PTHREAD 1)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
ENDIF(ENABLE_THREAD_UNSAFE MATCHES "ON")

CONFIGURE_FILE(config.h.in src/config.h)
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/src" "${CMAKE_BINARY_DIR}/src")

SET(LTPROTO_SRC src/ltproto.c 
				src/util.c
				src/objcache.c 
				${CMAKE_BINARY_DIR}/src/modules.c)
				
SET(MODULES_SRC src/null.c 
				src/udp_shmem.c
				src/unix_socket.c
				src/unix_shmem.c
				src/shmem.c)
SET(MODULES_LIST null udp_shmem unix unix_shmem shmem)

SET(ALLOCATORS_SRC	src/alloc_linear.c 
					src/alloc_system.c)
SET(ALLOCATORS_LIST linear system)

AddModules(MODULES_LIST)
AddAllocators(ALLOCATORS_LIST)

ADD_LIBRARY(ltproto SHARED ${LTPROTO_SRC} ${MODULES_SRC} ${ALLOCATORS_SRC})
IF(HAVE_LIBRT)
	TARGET_LINK_LIBRARIES(ltproto rt)
ENDIF(HAVE_LIBRT)
IF(OPENSSL_FOUND)
	TARGET_LINK_LIBRARIES(ltproto ${OPENSSL_LIBRARIES})
ENDIF(OPENSSL_FOUND)

SET_TARGET_PROPERTIES(ltproto PROPERTIES PUBLIC_HEADER "src/ltproto.h")

INSTALL(TARGETS ltproto LIBRARY PUBLIC_HEADER 
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib 
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
        
ADD_SUBDIRECTORY(test)
