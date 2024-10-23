#include "jni.h"
#include "string.h"
#include "android/log.h"
#include "stdio.h"
#include "sys/stat.h"
#include "malloc.h"
#include "stdbool.h"
#include "dirent.h"
#include "rc4.h"

#define PROC_TASK "/proc/self/task/"
#define PROC_MAPS "/proc/self/maps"
#define FRIDA_GMAIN "gmain"
#define FRIDA_GUM "gum-js-loop"
#define JIT_CACHE "jit-cache"
#define FRIDA "frida"
#define MAX_SIZE 256

#define ERROR_001 "Unsafe environment detected, please try again using a different device."
#define ERROR_002 "Couldn't open process tasks, something's wrong."
#define ERROR_003 "Debugger detected!"
#define ERROR_004 "Zygisk injection detected!"
#define ERROR_005 "Frida detected!"
#define ERROR_006 "Generic process injection detected!"

char enc_flag[] = "\x85\xf4\xaf\xce\xa7\xd8\xb6\x29\xdc\xae\x61\xb7\x58\x6c\x79\x8a\x2b\x34\xea\x59\x19\xa0";

void log_i(char* msg){
    __android_log_print(ANDROID_LOG_INFO, "SGC", "[*] %s", msg);
}

void force_crash(){
    typedef int (*fnc_ptr)();
    fnc_ptr fnc = (fnc_ptr)0x0;
    fnc();
}

bool check_debugger(char* line){
    if (strstr(line, "TracerPid") != NULL) {
        int tracerpid = 0;
        sscanf(line, "TracerPid: %d", &tracerpid);
        if (tracerpid != 0) {
            log_i(ERROR_003);
            return true;
        }
    }
}

bool check_frida_thread(char* line){
    char tname[MAX_SIZE] = "\x00";
    sscanf(line, "Name: %s", tname);
    if (strlen(tname) != 0 && (strcmp(tname, FRIDA_GMAIN) == 0 || strcmp(tname, FRIDA_GUM) == 0)) {
        log_i(ERROR_005);
        return true;
    }
    return false;
}

bool check_tasks(){
    bool result = false;
    DIR* dir = opendir(PROC_TASK);
    if (dir == NULL){
        log_i(ERROR_002);
        return result;
    }
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        char status_path[MAX_SIZE];
        snprintf(status_path, MAX_SIZE, "%s%s/status", PROC_TASK, entry->d_name);
        FILE *f = fopen(status_path, "r");
        if (f == NULL){
            continue;
        }

        char line[MAX_SIZE];
        while (fgets(line, MAX_SIZE, f) != NULL) {
            if (check_frida_thread(line) || check_debugger(line)){
                result = true;
                break;
            }

            if (result)
                break;
        }
    }
    return result;
}

int n_exe_jit_cache = 0;
int n_jit_cache_entries = 0;
bool check_zygisk_injection(char* pathname, char* perms){
    if (strstr(pathname, JIT_CACHE) == NULL)
        return false;

    n_jit_cache_entries += 1;
    if (strlen(perms) >= 4 && perms[2] == 'x')
        n_exe_jit_cache += 1;

    if (n_jit_cache_entries > 4 || n_exe_jit_cache > 1){
        log_i(ERROR_004);
        return true;
    }
    return false;
}

bool check_frida_agent_maps(char* pathname){
    if (strstr(pathname, FRIDA) != NULL){
        log_i(ERROR_005);
        return true;
    }
    return false;
}

bool check_rwx_anon_maps(char* inode, char* perms){
    if (strcmp(inode, "0") == 0 && strcmp(perms, "rwxp") == 0){
        log_i(ERROR_006);
        return true;
    }
    return false;
}

bool check_maps(){
    FILE *f = fopen(PROC_MAPS, "r");
    char line[MAX_SIZE];
    char addr_range[MAX_SIZE];
    char perms[5];
    char offset[MAX_SIZE];
    char dev[5];
    char inode[MAX_SIZE];
    char pathname[MAX_SIZE];
    bool result = false;

    memset(pathname, '\x00', MAX_SIZE);
    while((fgets(line, MAX_SIZE, f)) != NULL){
        sscanf(line, "%s %s %s %s %s %s", addr_range, perms, offset, dev, inode, pathname);

        if (check_zygisk_injection(pathname, perms) || check_frida_agent_maps(pathname) ||
                check_rwx_anon_maps(inode, perms)){
            result = true;
            break;
        }
    }
    n_jit_cache_entries = 0;
    n_exe_jit_cache = 0;

    return result;
}
__attribute__ ((visibility ("default")))
bool Java_com_sgc_nativetest_MainActivity_verifyFlag(JNIEnv *env, jobject thiz, jstring flag) {
    log_i("Beginning environment checks...");
    if (check_maps() || check_tasks()){
        force_crash();
        log_i(ERROR_001);
        return false;
    }
    else{
        log_i("Environment checks successful :)");
    }

    char key[] = "jtsecAls0Rules!";
    unsigned char* padded_enc_flag = (unsigned char*)malloc(MAX_SIZE);
    memset(padded_enc_flag, '\x00', MAX_SIZE);
    memcpy(padded_enc_flag, enc_flag, strlen(enc_flag));

    char* user_flag = (*env)->GetStringUTFChars(env, flag, 0);
    unsigned char* padded_user_flag = (unsigned char*)malloc(MAX_SIZE);
    memset(padded_user_flag, '\x00', MAX_SIZE);
    RC4(key, user_flag, padded_user_flag);

    return memcmp(padded_user_flag, padded_enc_flag, MAX_SIZE) == 0;
}