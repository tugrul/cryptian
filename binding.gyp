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
                "addon/lib/algorithm/saferplus.cc",
                "addon/lib/algorithm/tripledes.cc",
                "addon/lib/algorithm/wake.cc",
                "addon/lib/algorithm/xtea.cc",
                "addon/lib/algorithm/dummy.cc",
                "addon/lib/mode/cbc.cc",
                "addon/lib/mode/cfb.cc",
                "addon/lib/mode/ctr.cc",
                "addon/lib/mode/ecb.cc",
                "addon/lib/mode/ncfb.cc",
                "addon/lib/mode/nofb.cc",
                "addon/lib/mode/ofb.cc",
                "addon/src/node/cryptian.cc"
            ],
            "cflags": ["-std=c++11"],
            "include_dirs": [
                "<!(node -e \"require('nan')\")",
                "addon/lib/"
            ]
        }
    ]
}