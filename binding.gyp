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
                "addon/lib/algorithm/panama.cc",
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
                    # The Windows releases of Node 26 are built with clang and
                    # thin LTO, and common.gypi hands the options for that to
                    # every addon: -flto=thin and /opt:lldltojobs=N. Addons
                    # are built with MSVC. cl ignores -flto=thin with D9002,
                    # and link.exe stops at /opt:lldltojobs=N with LNK1117.
                    # Upstream report: nodejs/node#64674.
                    #
                    # node-gyp 13 switches the options off, and CI builds with
                    # node-gyp 13. The node-gyp that npm brings along in Node
                    # 26 is 12.4.0 and does not, and that is the one "npm
                    # install" uses. So the options are taken out here, by
                    # pattern because N varies.
                    "msvs_settings": {
                        "VCCLCompilerTool": {
                            "AdditionalOptions/": [["exclude", "^-flto"]]
                        },
                        "VCLibrarianTool": {
                            "AdditionalOptions/": [["exclude", "^-flto"]]
                        },
                        "VCLinkerTool": {
                            "AdditionalOptions/": [
                                ["exclude", "^-flto"],
                                ["exclude", "^/opt:lldltojobs"]
                            ]
                        }
                    }
                }]
            ]
        }
    ]
}
