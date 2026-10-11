{
  "variables": {
    "unv_sdk_dir%": "<!(python -c \"import os; print(os.environ.get('UNV_SDK_DIR', ''))\")"
  },
  "targets": [
    {
      "target_name": "uniview_native",
      "sources": ["src/addon.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<(unv_sdk_dir)/include"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": ["<(unv_sdk_dir)/lib/NetDEVSDK.lib"]
          }
        ]
      ],
      "msvs_settings": {
        "VCCLCompilerTool": { "ExceptionHandling": 1 }
      }
    }
  ]
}
