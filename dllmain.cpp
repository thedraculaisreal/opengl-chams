// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#define GL_ALWAYS 0x0207

HMODULE openGLHandle = NULL;

void (__stdcall *glDepthFunc)(unsigned int) = NULL;
void(__stdcall* glDepthRange)(double, double) = NULL;
void(__stdcall* glColor4f)(float, float, float, float) = NULL;
void(__stdcall* glEnable)(unsigned int) = NULL;
void(__stdcall* glDisable)(unsigned int) = NULL;
void(__stdcall* glEnableClientState)(unsigned int) = NULL;
void(__stdcall* glDisableClientState)(unsigned int) = NULL;

unsigned char* hook_location; 

DWORD ret_address = 0;
DWORD old_protect;
DWORD count = 0;



__declspec(naked) void codecave() {
    __asm {
        pushad
        mov eax, dword ptr ds:[esp+0x10] 
        mov count, eax
        popad
        pushad
    }
    // Disables depth rendering, and other rendering to render a solid state color over the players model
    if (count > 500) {
        (*glDepthRange)(0.0, 0.0); // makes depth testing obselete
        (*glDepthFunc)(0x207); // 0x207 = GL_ALWAYS, meaning always rendering every object.
        (*glDisableClientState)(0x8078); // disables textures
        (*glDisableClientState)(0x8076); // disables textures
        (*glEnable)(0x0B57);
        (*glColor4f)(1.0f, 0.6f, 0.6f, 1.0f); // sets color to red
    }
    else {
        (*glDepthRange)(0.0, 1.0); // restores default depth mapping.
        (*glDepthFunc)(0x203); // sets default behavior for depth testing
        (*glEnableClientState)(0x8078); // enables client side GL_TEXTURE_COORD_ARRAY
        (*glEnableClientState)(0x8076); // enables client side GL_VERTEX_ARRAY
        (*glDisable)(0x0B57);
        (*glColor4f)(1.0f, 1.0f, 1.0f, 1.0f); // sets color to white incase of bugs

    }

    __asm {
        popad
        mov esi, dword ptr ds : [esi + 0xA18]
        jmp ret_address
    }
}

void injected_thread() {
    while (true) {
        if (openGLHandle == NULL) {
            openGLHandle = GetModuleHandle(L"opengl32.dll");
        }

        if (openGLHandle != NULL) {
            glDepthFunc = (void(__stdcall*)(unsigned int))GetProcAddress(openGLHandle, "glDepthFunc"); // Grabbing module handles (base_addreses)
            glDepthRange = (void(__stdcall*)(double, double))GetProcAddress(openGLHandle, "glDepthRange");
            glColor4f = (void(__stdcall*)(float, float, float, float))GetProcAddress(openGLHandle, "glColor4f");
            glEnable = (void(__stdcall*)(unsigned int))GetProcAddress(openGLHandle, "glEnable");
            glDisable = (void(__stdcall*)(unsigned int))GetProcAddress(openGLHandle, "glDisable");
            glEnableClientState = (void(__stdcall*)(unsigned int))GetProcAddress(openGLHandle, "glEnableClientState");
            glDisableClientState = (void(__stdcall*)(unsigned int))GetProcAddress(openGLHandle, "glDisableClientState");

            hook_location = (unsigned char*)GetProcAddress(openGLHandle, "glDrawElements"); // where are hook begins
            hook_location += 0x16; // adding offset to hook location

            VirtualProtect((void*)hook_location, 5, PAGE_EXECUTE_READWRITE, &old_protect); // Set are permissions to read and write so we can set
            *hook_location = 0xE9;                                                         // a jump to our codecave 0xE9 = jmp in assembly
            *(DWORD*)(hook_location + 1) = (DWORD)&codecave - ((DWORD)hook_location + 5); // formula for jmping to codecave location
            *(hook_location + 5) = 0x90;

            ret_address = (DWORD)(hook_location + 0x6); // our ret address in codecave
        }

        Sleep(1);
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)injected_thread, NULL, NULL, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

