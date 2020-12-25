set(PROJECT_NAME Fubuki)

################################################################################
# Source groups
################################################################################
set(Header_Files
    "../Shared/minirtl.h"
    "../Shared/shared.h"
    "../Shared/util.h"
    "../Shared/windefend.h"
    "fubuki.h"
    "resource.h"
    "uihacks.h"
    "winmm.h"
)
source_group("Header Files" FILES ${Header_Files})

set(Source_Files
    "../Shared/util.c"
    "../Shared/windefend.c"
    "dllmain.c"
    "export.def"
    "uihacks.c"
)
source_group("Source Files" FILES ${Source_Files})

set(minirtl
    "../Shared/_filename.c"
    "../Shared/_filename.h"
    "../Shared/_strcat.c"
    "../Shared/_strcmpi.c"
    "../Shared/_strcpy.c"
    "../Shared/_strend.c"
    "../Shared/_strlen.c"
    "../Shared/_strncpy.c"
    "../Shared/_strstri.c"
    "../Shared/cmdline.c"
    "../Shared/cmdline.h"
    "../Shared/u64tostr.c"
    "../Shared/ultohex.c"
    "../Shared/ultostr.c"
)
source_group("minirtl" FILES ${minirtl})

set(ALL_FILES
    ${Header_Files}
    ${Source_Files}
    ${minirtl}
)

################################################################################
# Target
################################################################################
add_library(${PROJECT_NAME} SHARED ${ALL_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "NanoDesu")

use_props(${PROJECT_NAME} "${CMAKE_CONFIGURATION_TYPES}" "${DEFAULT_CXX_PROPS}")
set(ROOT_NAMESPACE dll)

set_target_properties(${PROJECT_NAME} PROPERTIES
    VS_GLOBAL_KEYWORD "Win32Proj"
)
################################################################################
# Target name
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_DEBUG              "${PROJECT_NAME}32"
        TARGET_NAME_RELEASE            "${PROJECT_NAME}32"
        TARGET_NAME_RELEASEINTERNAL    "${PROJECT_NAME}64"
        TARGET_NAME_RELEASEINTERNALDLL "${PROJECT_NAME}32"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_DEBUG              "${PROJECT_NAME}32"
        TARGET_NAME_RELEASE            "${PROJECT_NAME}32"
        TARGET_NAME_RELEASEINTERNAL    "${PROJECT_NAME}32"
        TARGET_NAME_RELEASEINTERNALDLL "${PROJECT_NAME}32"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    set_target_properties(${PROJECT_NAME} PROPERTIES
        TARGET_NAME_DEBUG              "${PROJECT_NAME}64"
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
        $<$<CONFIG:Debug>:
            MultiThreadedDLL
        >
        $<$<CONFIG:Release>:
            MultiThreadedDLL
        >
        $<$<CONFIG:ReleaseInternalDll>:
            MultiThreadedDLL
        >
        $<$<NOT:$<OR:$<CONFIG:Debug>,$<CONFIG:Release>,$<CONFIG:ReleaseInternalDll>>>:${MSVC_RUNTIME_LIBRARY_DEFAULT}>
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    string(CONCAT "MSVC_RUNTIME_LIBRARY_STR"
        MultiThreadedDLL
    )
endif()
set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY ${MSVC_RUNTIME_LIBRARY_STR})

################################################################################
# Include directories
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    target_include_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/.."
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    target_include_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/.."
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    target_include_directories(${PROJECT_NAME} PRIVATE
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
        "WIN32;"
        "_WINDOWS;"
        "_USRDLL;"
        "DLL_EXPORTS;"
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
        "WIN32;"
        "_WINDOWS;"
        "_USRDLL;"
        "DLL_EXPORTS;"
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
        "WIN32;"
        "_WINDOWS;"
        "_USRDLL;"
        "DLL_EXPORTS;"
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
                /O1;
                /Oi;
                /Gy
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O1;
                /Oi;
                /Gy;
                ${DEFAULT_CXX_EXCEPTION_HANDLING}
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /O1;
                /Oi;
                /Gy
            >
            /GF;
            /W4;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            /Os;
            /TC;
            /GS-;
            /Y-
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
        target_compile_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /Od
            >
            $<$<CONFIG:Release>:
                /MP;
                /O1;
                /Oi;
                /Gy
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O1;
                /Oi;
                /Gy
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /O1;
                /Oi;
                /Gy
            >
            /GF;
            /W4;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            /Os;
            /TC;
            /GS-;
            /Y-
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
        target_compile_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /Od
            >
            $<$<CONFIG:Release>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os
            >
            $<$<CONFIG:ReleaseInternal>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MP;
                /O1;
                /Oi;
                /GF;
                /Gy;
                /Os
            >
            /W4;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            /TC;
            ${DEFAULT_CXX_EXCEPTION_HANDLING};
            /GS-;
            /Y-
        )
    endif()
    if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
        target_link_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /MANIFEST:NO;
                /INCREMENTAL
            >
            $<$<CONFIG:Release>:
                /MANIFEST;
                /DEBUG:FULL;
                /OPT:REF;
                /LTCG;
                /OPT:ICF
            >
            $<$<CONFIG:ReleaseInternal>:
                /DEBUG:FULL;
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL:NO
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MANIFEST;
                /DEBUG:FULL;
                /OPT:REF;
                /LTCG;
                /OPT:ICF
            >
            /SUBSYSTEM:WINDOWS
        )
    elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
        target_link_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /MANIFEST:NO;
                /INCREMENTAL
            >
            $<$<CONFIG:Release>:
                /MANIFEST;
                /DEBUG:FULL;
                /OPT:REF;
                /LTCG;
                /OPT:ICF
            >
            $<$<CONFIG:ReleaseInternal>:
                /MANIFEST;
                /DEBUG:FULL;
                /OPT:REF;
                /LTCG;
                /OPT:ICF
            >
            $<$<CONFIG:ReleaseInternalDll>:
                /MANIFEST;
                /DEBUG:FULL;
                /OPT:REF;
                /LTCG;
                /OPT:ICF
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
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Fubuki64.dll
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Fubuki32.dll
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    add_custom_command_if(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMANDS
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Fubuki32.dll
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Fubuki32.dll
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    add_custom_command_if(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMANDS
        COMMAND    $<CONFIG:ReleaseInternal> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Fubuki64.dll
        COMMAND $<CONFIG:ReleaseInternalDll> \\Utils\\StripDebug.exe .\\output\\${CMAKE_VS_PLATFORM_NAME}\\$<CONFIG>\\Fubuki64.dll
    )
endif()

################################################################################
# Dependencies
################################################################################
if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Any CPU")
    set(ADDITIONAL_LIBRARY_DEPENDENCIES
        "Shell32"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    set(ADDITIONAL_LIBRARY_DEPENDENCIES
        "Shell32"
    )
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    set(ADDITIONAL_LIBRARY_DEPENDENCIES
        "Shell32"
    )
endif()
target_link_libraries(${PROJECT_NAME} PUBLIC "${ADDITIONAL_LIBRARY_DEPENDENCIES}")

