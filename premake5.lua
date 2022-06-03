newoption {
    trigger     = "outdir",
    value       = "path",
    description = "Output directory for the build files"
}
if not _OPTIONS["outdir"] then
    _OPTIONS["outdir"] = "Build"
end


--[[
    The Solution
--]]

solution "h9"

    configurations { "Release", "Debug" }

    location( _OPTIONS["outdir"] )
    targetdir "Bin"
    implibdir "Bin"
    flags { symbols ("On") }  

    configuration "Release*"
        defines { "NDEBUG" }
        optimize "Full"

    filter "system:windows"
        buildoptions {"/MD"}

    filter "system:windows"
        flags {
            staticruntime("On"),
            "NoImportLib",
            rtti ("Off"),
            "NoBufferSecurityCheck"
        }
        defines { "_CRT_SECURE_NO_WARNINGS", "_SCL_SECURE_NO_WARNINGS"}

group ""
        project "h9"
            vpaths {
                ["Headers/*"] = {"h9/**.h*",},
                ["Sources/*"] = {"h9/**.c*",},
                ["*"] = {"premake5.lua"}
            }
            defines { }
            includedirs { "h9", "h9/**" }
            links { }
        language "C++"
        kind "ConsoleApp"
        targetname "h9"         
        files {
            "h9/**.h*",
            "h9/**.c*"
        }
