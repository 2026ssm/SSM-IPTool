{
  "variables": {
    "dahua_sdk_dir%": "<!(python -c \"import os; print(os.environ.get('DAHUA_SDK_DIR', ''))\")"
  },
  "targets": [
    {
      "target_name": "dahua_native",
      "sources": ["src/addon.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<(dahua_sdk_dir)/Include/Common"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "<(dahua_sdk_dir)/Lib/Win64/dhnetsdk.lib"
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
