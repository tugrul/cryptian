{
    "targets": [
        {
            "target_name": "cryptian",
            "sources": [
                "addon/lib/algorithm/threeway.cc",
                "addon/lib/algorithm/arcfour.cc",
                "addon/lib/algorithm/blowfish.cc",
                "addon/lib/algorithm/cast-128.cc",
                "addon/lib/algorithm/cast-256.cc",
                "addon/lib/algorithm/des.cc",
                "addon/lib/algorithm/enigma.cc",
                "addon/lib/algorithm/gost.cc",
                "addon/lib/algorithm/loki97.cc",
                "addon/lib/algorithm/rc2.cc",
                "addon/lib/algorithm/rijndael.cc",
                "addon/lib/algorithm/safer.cc",
                "addon/lib/algorithm/serpent.cc",
                "addon/lib/algorithm/saferplus.cc",
                "addon/lib/algorithm/tripledes.cc",
                "addon/lib/algorithm/twofish.cc",
                "addon/lib/algorithm/wake.cc",
                "addon/lib/algorithm/xtea.cc",
                "addon/lib/algorithm/dummy.cc",
                "addon/lib/mode/cbc.cc",
                "addon/lib/mode/pcbc.cc",
                "addon/lib/mode/cfb.cc",
                "addon/lib/mode/ctr.cc",
                "addon/lib/mode/ecb.cc",
                "addon/lib/mode/ncfb.cc",
                "addon/lib/mode/nofb.cc",
                "addon/lib/mode/ofb.cc",
                "addon/src/node/cryptian.cc"
            ],
            "cflags_cc": ["-std=c++20"],
            "cflags_cc!": ["-std=c++17", "-std=gnu++17", "-fno-exceptions"],
            "include_dirs": [
                "<!(node -e \"require('nan')\")",
                "addon/lib/"
            ],
            "xcode_settings": {
                'CLANG_CXX_LANGUAGE_STANDARD': 'c++20',
                'CLANG_CXX_LIBRARY': 'libc++'
            },
            "msvs_settings": {
                "VCCLCompilerTool": {
                    "AdditionalOptions": ["/std:c++20"]
                }
            },
            "conditions": [
                ["OS=='win'", {
                    # Node 26 reports enable_thin_lto true in the generated
                    # config.gypi even when the addon is compiled with MSVC
                    # rather than clang, so common.gypi contributes clang and
                    # lld only options to an MSVC project. cl ignores
                    # -flto=thin with D9002 and link.exe rejects
                    # /opt:lldltojobs=N with LNK1117, which fails the build.
                    # Upstream report: nodejs/node#64674.
                    #
                    # lto_jobs is emptied so the condition that adds the
                    # linker option cannot fire, and the -flto options are
                    # removed from each tool. lto_jobs is not referenced by
                    # expansion anywhere here because it is absent from the
                    # config.gypi of older releases.
                    "variables": {
                        "enable_thin_lto": "false",
                        "lto_jobs": ""
                    },
                    "msvs_settings": {
                        "VCCLCompilerTool": {
                            "AdditionalOptions!": ["-flto=thin", "-flto=full"]
                        },
                        "VCLibrarianTool": {
                            "AdditionalOptions!": ["-flto=thin", "-flto=full"]
                        },
                        "VCLinkerTool": {
                            "AdditionalOptions!": ["-flto=thin", "-flto=full"]
                        }
                    }
                }]
            ]
        }
    ]
}
