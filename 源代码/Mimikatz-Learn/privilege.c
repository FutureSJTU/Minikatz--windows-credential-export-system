/* privilege 模块实现管理员启用 SeDebugPrivilege 特权的功能 */
#include "privilege.h"
#include <stdio.h>

// EnableSeDebugPrivilege 函数负责启用管理员账户默认禁用的 SeDebugPrivilege 权限 *
/// 推荐使用API: OpenProcessToken() LookupPrivilegeValueW() AdjustTokenPrivileges()
BOOL EnableSeDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    // 打开当前进程的访问令牌
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;

    // 获取 SeDebugPrivilege 权限的本地唯一标识符
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

    // 设置访问令牌的特权级别
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // 调整访问令牌的特权级别
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) return FALSE;

    return TRUE;
}

/// Checks the corresponding Windows privilege and returns True or False.
BOOL CheckWindowsPrivilege(IN PWCHAR Privilege) {
    LUID luid;
    PRIVILEGE_SET privs = { 0 };
    HANDLE hProcess;
    HANDLE hToken;
    hProcess = GetCurrentProcess();
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
    if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) return FALSE;
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL bResult;
    PrivilegeCheck(hToken, &privs, &bResult);
    return bResult;
}

/// 启用Administrator的SeDebugPrivilege权限
VOID AdjustProcessPrivilege() {
    BOOL success = EnableSeDebugPrivilege();
    if (!success || !CheckWindowsPrivilege((WCHAR*)SE_DEBUG_NAME)) {
        printf("AdjustProcessPrivilege() not working ...\n");
        printf("Are you running as Admin ? ...\n");
        ExitProcess(-1);
    } else {
        printf("\n[+] AdjustProcessPrivilege() ok .\n\n");
    }
}