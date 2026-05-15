#include <windows.h>

// simple C code that open calc. shellcode generated using donut
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WinExec("calc.exe", SW_SHOW);
    return 0;
}
