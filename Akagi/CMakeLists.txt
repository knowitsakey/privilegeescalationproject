set(PROJECT_NAME Akagi)

################################################################################
# Source groups
################################################################################
set(Header_Files
    "../Shared/minirtl.h"
    "../Shared/rtltypes.h"
    "../Shared/shared.h"
    "../Shared/windefend.h"
    "aic.h"
    "compress.h"
    "encresource.h"
    "export.def"
    "global.h"
    "makecab.h"
    "mycode.cpp"
    "mycode.h"
    "resource.h"
    "stub.h"
    "sup.h"
)
source_group("Header Files" FILES ${Header_Files})

set(Source_Files
    "../Shared/windefend.c"
    "aic.c"
    "compress.c"
    "main.c"
    "makecab.c"
    "stub.c"
    "sup.c"
)
source_group("Source Files" FILES ${Source_Files})

set(Source_Files__methods
    "methods/api0cradle.c"
    "methods/api0cradle.h"
    "methods/comsup.c"
    "methods/comsup.h"
    "methods/dwells.c"
    "methods/dwells.h"
    "methods/elvint.h"
    "methods/hakril.c"
    "methods/hakril.h"
    "methods/hybrids.c"
    "methods/hybrids.h"
    "methods/methods.c"
    "methods/methods.h"
    "methods/rinn.c"
    "methods/rinn.h"
    "methods/shellsup.c"
    "methods/shellsup.h"
    "methods/tyranid.c"
    "methods/tyranid.h"
    "methods/wusa.c"
    "methods/wusa.h"
)
source_group("Source Files\\methods" FILES ${Source_Files__methods})

set(appinfo
    "appinfo/x64/appinfo64.c"
    "appinfo/x86-32/appinfo32.c"
)
source_group("appinfo" FILES ${appinfo})

set(ldr
    "../Shared/ldr.c"
    "../Shared/ldr.h"
)
source_group("ldr" FILES ${ldr})

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
    "../Shared/_strncmpi.c"
    "../Shared/_strncpy.c"
    "../Shared/_strstri.c"
    "../Shared/cmdline.c"
    "../Shared/strtoul.c"
    "../Shared/u64tohex.c"
    "../Shared/u64tostr.c"
    "../Shared/ultohex.c"
    "../Shared/ultostr.c"
)
source_group("minirtl" FILES ${minirtl})

set(testunits
    "tests/test.c"
    "tests/test.h"
)
source_group("testunits" FILES ${testunits})

set(ALL_FILES
    ${Header_Files}
    ${Source_Files}
    ${Source_Files__methods}
    ${appinfo}
    ${ldr}
    ${minirtl}
    ${testunits}
)

################################################################################
# Target
################################################################################
add_executable(${PROJECT_NAME} ${ALL_FILES})

use_props(${PROJECT_NAME} "${CMAKE_CONFIGURATION_TYPES}" "${DEFAULT_CXX_PROPS}")
set(ROOT_NAMESPACE uacme)

set_target_properties(${PROJECT_NAME} PROPERTIES
    VS_GLOBAL_KEYWORD "Win32Proj"
)
################################################################################
# Target name
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_RELEASE            "${PROJECT_NAME}32"
        TARGET_NAME_RELEASEINTERNAL    "${PROJECT_NAME}64"
        TARGET_NAME_RELEASEINTERNALDLL "${PROJECT_NAME}32"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_RELEASE            "${PROJECT_NAME}32"
        TARGET_NAME_RELEASEINTERNAL    "${PROJECT_NAME}32"
        TARGET_NAME_RELEASEINTERNALDLL "${PROJECT_NAME}32"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_RELEASE            "${PROJECT_NAME}64"
        TARGET_NAME_RELEASEINTERNAL    "${PROJECT_NAME}64"
        TARGET_NAME_RELEASEINTERNALDLL "${PROJECT_NAME}64"
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
            "NDEBUG;"
            "COMPILE_AS_DLL"
        ">"
        "WIN32;"
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
            "NDEBUG;"
            "COMPILE_AS_DLL"
        ">"
        "WIN32;"
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
            "DEBUG;"
            "COMPILE_AS_DLL"
        ">"
        "WIN32;"
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
                /Od;
                /sdl
            >
            $<$<CONFIG:Release>:
                /MP;
                /O2;
                /Oi;
                /Gy;
                /Os;
                /TC;
                /GS-
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O1;
                /Oi;
                /Gy;
                /Os;
                /TC;
                /GS-
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /O2;
                /Oi;
                /Gz;
                /Gy;
                /Os;
                /TC;
                /GS-
            >
            /GF;
            /W4;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            ${DEFAULT_CXX_EXCEPTION_HANDLING};
            /Y-
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
        target_compile_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /Od;
                /sdl
            >
            $<$<CONFIG:Release>:
                /MP;
                /O2;
                /Oi;
                /Gy;
                /Os;
                /TC;
                /GS-
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O2;
                /Oi;
                /Gz;
                /Gy;
                /Os;
                /TC;
                /GS-
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /O2;
                /Oi;
                /Gz;
                /Gy;
                /Os;
                /TC;
                /GS-
            >
            /GF;
            /W4;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            ${DEFAULT_CXX_EXCEPTION_HANDLING};
            /Y-
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
        target_compile_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /Od;
                /sdl;
                /W1
            >
            $<$<CONFIG:Release>:
                /MP;
                /O1;
                /Oi;
                /Gy;
                /W4;
                /Os;
                /TC;
                /GS-
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O1;
                /Oi;
                /Gy;
                /W4;
                /Os;
                /TC;
                /GS-
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /GL-;
                /Od;
                /Oi;
                /Gy;
                /W4;
                /TC;
                /GS-
            >
            /GF;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
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
                /DEBUG:FULL;
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
                /DEBUG:FULL;
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            /SUBSYSTEM:WINDOWS
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
        target_link_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /DEBUG;
                /INCREMENTAL
            >
            $<$<CONFIG:Release>:
                /DEBUG:FULL;
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternal>:
                /DEBUG:FULL;
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /DEBUG:FULL;
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            /SUBSYSTEM:WINDOWS
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
                /DEBUG;
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            /SUBSYSTEM:WINDOWS
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
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Akagi64.exe
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Akagi32.exe
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    add_custom_command_if(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMANDS
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Akagi32.exe
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Akagi32.exe
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    add_custom_command_if(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMANDS
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Akagi64.exe
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Akagi64.exe
    )
endif()

