// dvrdvstypedef.h (part of TVT's real SDK) #includes "stdafx.h" assuming
// it's built inside their MFC demo project, where that file is generated
// per-project and pulls in windows.h/basic Windows types. Outside that
// project it doesn't exist at all. All it actually needs is DWORD and
// friends, so a stub that just pulls in windows.h satisfies it. Same fix
// as SSM-VMS's own native/tvt/src/stdafx.h.
#pragma once
#include <windows.h>
