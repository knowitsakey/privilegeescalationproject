set(PROJECT_NAME Yuubari)

################################################################################
# Source groups
################################################################################
set(Header_Files
    "../Shared/minirtl.h"
    "../Shared/ntos.h"
    "../Shared/ntsxs.h"
    "../Shared/rtltypes.h"
    "appinfo.h"
    "basic.h"
    "comobj.h"
    "consts.h"
    "cui.h"
    "fusion.h"
    "global.h"
    "logger.h"
    "patterns.h"
    "resource.h"
    "sup.h"
    "wintrustex.h"
)
source_group("Header Files" FILES ${Header_Files})

set(Source_Files
    "appinfo.c"
    "basic.c"
    "comobj.c"
    "cui.c"
    "fusion.c"
    "logger.c"
    "main.c"
    "sup.c"
)
source_group("Source Files" FILES ${Source_Files})

set(hde
    "../Shared/hde/hde64.c"
    "../Shared/hde/hde64.h"
    "../Shared/hde/pstdint.h"
    "../Shared/hde/table64.h"
)
source_group("hde" FILES ${hde})

set(minirtl
    "../Shared/_filename.c"
    "../Shared/_filename.h"
    "../Shared/_strcat.c"
    "../Shared/_strcmp.c"
    "../Shared/_strcmpi.c"
    "../Shared/_strcpy.c"
    "../Shared/_strend.c"
    "../Shared/_strlen.c"
    "../Shared/_strncmp.c"
    "../Shared/_strncpy.c"
    "../Shared/cmdline.c"
    "../Shared/cmdline.h"
    "../Shared/strtoi.c"
    "../Shared/ultostr.c"
)
source_group("minirtl" FILES ${minirtl})

set(testunits
    "tests/test_fusion.c"
    "tests/test_fusion.h"
)
source_group("testunits" FILES ${testunits})

set(ALL_FILES
    ${Header_Files}
    ${Source_Files}
    ${hde}
    ${minirtl}
    ${testunits}
)

################################################################################
# Target
################################################################################
add_executable(${PROJECT_NAME} ${ALL_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "NanoDesu")

use_props(${PROJECT_NAME} "${CMAKE_CONFIGURATION_TYPES}" "${DEFAULT_CXX_PROPS}")
set(ROOT_NAMESPACE Yuubari)

set_target_properties(${PROJECT_NAME} PROPERTIES
    VS_GLOBAL_KEYWORD "Win32Proj"
)
################################################################################
# Target name
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_RELEASE            "UacInfo64"
        TARGET_NAME_RELEASEINTERNAL    "UacInfo64"
        TARGET_NAME_RELEASEINTERNALDLL "UacInfo64"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_RELEASE            "UacInfo64"
        TARGET_NAME_RELEASEINTERNAL    "UacInfo64"
        TARGET_NAME_RELEASEINTERNALDLL "UacInfo64"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_RELEASE            "UacInfo64"
        TARGET_NAME_RELEASEINTERNAL    "UacInfo64"
        TARGET_NAME_RELEASEINTERNALDLL "UacInfo64"
    )
endif()
################################################################################
# Output directory
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        OUTPUT_DIRECTORY_DEBUG              "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASE            "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASEINTERNAL    "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASEINTERNALDLL "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        OUTPUT_DIRECTORY_DEBUG              "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASE            "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASEINTERNAL    "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASEINTERNALDLL "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        OUTPUT_DIRECTORY_DEBUG              "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASE            "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASEINTERNAL    "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
        OUTPUT_DIRECTORY_RELEASEINTERNALDLL "${CMAKE_CURRENT_SOURCE_DIR}/./output/${CMAKE_VS_PLATFORM_NAME}/$<CONFIG>/"
    )
endif()
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE            "TRUE"
        INTERPROCEDURAL_OPTIMIZATION_RELEASEINTERNAL    "TRUE"
        INTERPROCEDURAL_OPTIMIZATION_RELEASEINTERNALDLL "TRUE"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE            "TRUE"
        INTERPROCEDURAL_OPTIMIZATION_RELEASEINTERNAL    "TRUE"
        INTERPROCEDURAL_OPTIMIZATION_RELEASEINTERNALDLL "TRUE"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE            "TRUE"
        INTERPROCEDURAL_OPTIMIZATION_RELEASEINTERNAL    "TRUE"
        INTERPROCEDURAL_OPTIMIZATION_RELEASEINTERNALDLL "TRUE"
    )
endif()
################################################################################
# MSVC runtime library
################################################################################
get_property(MSVC_RUNTIME_LIBRARY_DEFAULT TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY)
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    string(CONCAT "MSVC_RUNTIME_LIBRARY_STR"
        $<$<CONFIG:Release>:
            MultiThreaded
        >
        $<$<CONFIG:ReleaseInternal>:
            MultiThreaded
        >
        $<$<CONFIG:ReleaseInternalDll>:
            MultiThreaded
        >
        $<$<NOT:$<OR:$<CONFIG:Release>,$<CONFIG:ReleaseInternal>,$<CONFIG:ReleaseInternalDll>>>:${MSVC_RUNTIME_LIBRARY_DEFAULT}>
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    string(CONCAT "MSVC_RUNTIME_LIBRARY_STR"
        $<$<CONFIG:Release>:
            MultiThreaded
        >
        $<$<CONFIG:ReleaseInternal>:
            MultiThreaded
        >
        $<$<CONFIG:ReleaseInternalDll>:
            MultiThreaded
        >
        $<$<NOT:$<OR:$<CONFIG:Release>,$<CONFIG:ReleaseInternal>,$<CONFIG:ReleaseInternalDll>>>:${MSVC_RUNTIME_LIBRARY_DEFAULT}>
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    string(CONCAT "MSVC_RUNTIME_LIBRARY_STR"
        $<$<CONFIG:Release>:
            MultiThreaded
        >
        $<$<CONFIG:ReleaseInternal>:
            MultiThreaded
        >
        $<$<CONFIG:ReleaseInternalDll>:
            MultiThreaded
        >
        $<$<NOT:$<OR:$<CONFIG:Release>,$<CONFIG:ReleaseInternal>,$<CONFIG:ReleaseInternalDll>>>:${MSVC_RUNTIME_LIBRARY_DEFAULT}>
    )
endif()
set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY ${MSVC_RUNTIME_LIBRARY_STR})

################################################################################
# Include directories
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    target_include_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/.;"
        "${CMAKE_CURRENT_SOURCE_DIR}/.."
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    target_include_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/.;"
        "${CMAKE_CURRENT_SOURCE_DIR}/.."
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    target_include_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/.;"
        "${CMAKE_CURRENT_SOURCE_DIR}/.."
    )
endif()

################################################################################
# Compile definitions
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        "$<$<CONFIG:Debug>:"
            "_DEBUG"
        ">"
        "$<$<CONFIG:Release>:"
            "NDEBUG"
        ">"
        "$<$<CONFIG:ReleaseInternal>:"
            "NDEBUG"
        ">"
        "$<$<CONFIG:ReleaseInternalDll>:"
            "NDEBUG"
        ">"
        "_WINDOWS;"
        "UNICODE;"
        "_UNICODE"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        "$<$<CONFIG:Debug>:"
            "_DEBUG"
        ">"
        "$<$<CONFIG:Release>:"
            "NDEBUG"
        ">"
        "$<$<CONFIG:ReleaseInternal>:"
            "NDEBUG"
        ">"
        "$<$<CONFIG:ReleaseInternalDll>:"
            "NDEBUG"
        ">"
        "_WINDOWS;"
        "UNICODE;"
        "_UNICODE"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        "$<$<CONFIG:Debug>:"
            "_DEBUG"
        ">"
        "$<$<CONFIG:Release>:"
            "NDEBUG"
        ">"
        "$<$<CONFIG:ReleaseInternal>:"
            "NDEBUG"
        ">"
        "$<$<CONFIG:ReleaseInternalDll>:"
            "NDEBUG"
        ">"
        "_WINDOWS;"
        "UNICODE;"
        "_UNICODE"
    )
endif()

################################################################################
# Compile and link options
################################################################################
if(MSVC)
    if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
        target_compile_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /Od
            >
            $<$<CONFIG:Release>:
                /MP;
                /O2;
                /Oi;
                /GF;
                /Gy;
                /guard:cf
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os;
                /guard:cf
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os;
                /guard:cf
            >
            /sdl;
            /W4;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            /TC;
            ${DEFAULT_CXX_EXCEPTION_HANDLING};
            /Y-
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
        target_compile_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /Od
            >
            $<$<CONFIG:Release>:
                /MP;
                /O2;
                /Oi;
                /GF;
                /Gy;
                /guard:cf
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os;
                /guard:cf
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os;
                /guard:cf
            >
            /sdl;
            /W4;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            /TC;
            ${DEFAULT_CXX_EXCEPTION_HANDLING};
            /Y-
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
        target_compile_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /Od
            >
            $<$<CONFIG:Release>:
                /MP;
                /O2;
                /Oi;
                /GF;
                /Gy;
                /guard:cf
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os;
                /guard:cf
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os;
                /guard:cf
            >
            /sdl;
            /W4;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            /TC;
            ${DEFAULT_CXX_EXCEPTION_HANDLING};
            /Y-
        )
    endif()
    if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
        target_link_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /DEBUG;
                /INCREMENTAL
            >
            $<$<CONFIG:Release>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternal>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            /SUBSYSTEM:CONSOLE
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
        target_link_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /DEBUG;
                /INCREMENTAL
            >
            $<$<CONFIG:Release>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternal>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            /SUBSYSTEM:CONSOLE
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
        target_link_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /DEBUG;
                /INCREMENTAL
            >
            $<$<CONFIG:Release>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternal>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            /SUBSYSTEM:CONSOLE
        )
    endif()
endif()

################################################################################
# Post build events
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    add_custom_command_if(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMANDS
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\UacInfo64.exe
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\UacInfo64.exe
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    add_custom_command_if(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMANDS
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\UacInfo64.exe
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\UacInfo64.exe
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    add_custom_command_if(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMANDS
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\UacInfo64.exe
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\UacInfo64.exe
    )
endif()

