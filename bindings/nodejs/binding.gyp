{
  "targets": [
    {
      "target_name": "secureapis",
      "sources": [
        "src/secureapis.cc"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "conditions": [
        ["OS=='linux'", {
          "libraries": [
            "../../target/release/libsecureapis.so"
          ],
          "library_dirs": [
            "../../target/release"
          ]
        }],
        ["OS=='mac'", {
          "libraries": [
            "../../target/release/libsecureapis.dylib"
          ],
          "library_dirs": [
            "../../target/release"
          ]
        }],
        ["OS=='win'", {
          "libraries": [
            "../../target/release/secureapis.dll.lib"
          ],
          "library_dirs": [
            "../../target/release"
          ]
        }]
      ]
    }
  ]
}