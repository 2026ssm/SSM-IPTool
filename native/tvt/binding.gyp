{
  "variables": {
    "tvt_sdk_dir%": "<!(python -c \"import os; print(os.environ.get('TVT_SDK_DIR', ''))\")"
  },
  "targets": [
    {
      "target_name": "tvt_native",
      "sources": ["src/addon.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "src",
        "<(tvt_sdk_dir)/include"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "<(tvt_sdk_dir)/Windows/bin_release/Release_vcx_x64/DVR_NET_SDK.lib"
            ]
          }
        ]
      ],
      "msvs_settings": {
        "VCCLCompilerTool": { "ExceptionHandling": 1 }
      }
    }
  ]
}
