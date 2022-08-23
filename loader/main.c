/* main.c -- tombraider .so loader
 *
 * Copyright (C) 2021 Andy Nguyen
 * Copyright (C) 2022 Rinnegatamante
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.	See the LICENSE file for details.
 */

#include <vitasdk.h>
#include <kubridge.h>
#include <vitashark.h>
#include <vitaGL.h>
#include <zlib.h>

#include <SDL2/SDL.h>
#include <SDL2/SDL_mixer.h>
#include <SDL2/SDL_image.h>
#include <SLES/OpenSLES.h>

#include <malloc.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <wchar.h>
#include <wctype.h>

#include <math.h>
#include <math_neon.h>

#include <errno.h>
#include <ctype.h>
#include <setjmp.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "main.h"
#include "config.h"
#include "dialog.h"
#include "so_util.h"
#include "sha1.h"

#ifdef DEBUG
#define dlog printf
#else
#define dlog
#endif

char DATA_PATH[256];

extern const char *BIONIC_ctype_;
extern const short *BIONIC_tolower_tab_;
extern const short *BIONIC_toupper_tab_;

uint8_t force_30fps = 1;

static char fake_vm[0x1000];
static char fake_env[0x1000];

int file_exists(const char *path) {
	SceIoStat stat;
	return sceIoGetstat(path, &stat) >= 0;
}

int _newlib_heap_size_user = MEMORY_NEWLIB_MB * 1024 * 1024;

unsigned int _pthread_stack_default_user = 1 * 1024 * 1024;

so_module tombraider_mod;

void *__wrap_memcpy(void *dest, const void *src, size_t n) {
	return sceClibMemcpy(dest, src, n);
}

void *__wrap_memmove(void *dest, const void *src, size_t n) {
	return sceClibMemmove(dest, src, n);
}

void *__wrap_memset(void *s, int c, size_t n) {
	return sceClibMemset(s, c, n);
}

char *getcwd_hook(char *buf, size_t size) {
	strcpy(buf, DATA_PATH);
	return buf;
}

int debugPrintf(char *text, ...) {
#ifdef DEBUG
	va_list list;
	static char string[0x8000];

	va_start(list, text);
	vsprintf(string, text, list);
	va_end(list);

	SceUID fd = sceIoOpen("ux0:data/tombraider_log.txt", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0777);
	if (fd >= 0) {
		sceIoWrite(fd, string, strlen(string));
		sceIoClose(fd);
	}
#endif
	return 0;
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
#ifdef DEBUG
	va_list list;
	static char string[0x8000];

	va_start(list, fmt);
	vsprintf(string, fmt, list);
	va_end(list);

	dlog("[LOG] %s: %s\n", tag, string);
#endif
	return 0;
}

int __android_log_write(int prio, const char *tag, const char *fmt, ...) {
#ifdef DEBUG
	va_list list;
	static char string[0x8000];

	va_start(list, fmt);
	vsprintf(string, fmt, list);
	va_end(list);

	dlog("[LOGW] %s: %s\n", tag, string);
#endif
	return 0;
}

int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list list) {
#ifdef DEBUG
	static char string[0x8000];

	vsprintf(string, fmt, list);
	va_end(list);

	dlog("[LOGV] %s: %s\n", tag, string);
#endif
	return 0;
}

int ret0(void) {
	return 0;
}

int ret1(void) {
	return 1;
}

int pthread_mutex_init_fake(pthread_mutex_t **uid, const pthread_mutexattr_t *mutexattr) {
	pthread_mutex_t *m = calloc(1, sizeof(pthread_mutex_t));
	if (!m)
		return -1;

	const int recursive = (mutexattr && *(const int *)mutexattr == 1);
	*m = recursive ? PTHREAD_RECURSIVE_MUTEX_INITIALIZER : PTHREAD_MUTEX_INITIALIZER;

	int ret = pthread_mutex_init(m, mutexattr);
	if (ret < 0) {
		free(m);
		return -1;
	}

	*uid = m;

	return 0;
}

int pthread_mutex_destroy_fake(pthread_mutex_t **uid) {
	if (uid && *uid && (uintptr_t)*uid > 0x8000) {
		pthread_mutex_destroy(*uid);
		free(*uid);
		*uid = NULL;
	}
	return 0;
}

int pthread_mutex_lock_fake(pthread_mutex_t **uid) {
	int ret = 0;
	if (!*uid) {
		ret = pthread_mutex_init_fake(uid, NULL);
	} else if ((uintptr_t)*uid == 0x4000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	} else if ((uintptr_t)*uid == 0x8000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	if (ret < 0)
		return ret;
	return pthread_mutex_lock(*uid);
}

int pthread_mutex_trylock_fake(pthread_mutex_t **uid) {
	int ret = 0;
	if (!*uid) {
		ret = pthread_mutex_init_fake(uid, NULL);
	} else if ((uintptr_t)*uid == 0x4000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	} else if ((uintptr_t)*uid == 0x8000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	if (ret < 0)
		return ret;
	return pthread_mutex_trylock(*uid);
}

int pthread_mutex_unlock_fake(pthread_mutex_t **uid) {
	int ret = 0;
	if (!*uid) {
		ret = pthread_mutex_init_fake(uid, NULL);
	} else if ((uintptr_t)*uid == 0x4000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	} else if ((uintptr_t)*uid == 0x8000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	if (ret < 0)
		return ret;
	return pthread_mutex_unlock(*uid);
}

int pthread_cond_init_fake(pthread_cond_t **cnd, const int *condattr) {
	pthread_cond_t *c = calloc(1, sizeof(pthread_cond_t));
	if (!c)
		return -1;

	*c = PTHREAD_COND_INITIALIZER;

	int ret = pthread_cond_init(c, NULL);
	if (ret < 0) {
		free(c);
		return -1;
	}

	*cnd = c;

	return 0;
}

int pthread_cond_broadcast_fake(pthread_cond_t **cnd) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_broadcast(*cnd);
}

int pthread_cond_signal_fake(pthread_cond_t **cnd) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_signal(*cnd);
}

int pthread_cond_destroy_fake(pthread_cond_t **cnd) {
	if (cnd && *cnd) {
		pthread_cond_destroy(*cnd);
		free(*cnd);
		*cnd = NULL;
	}
	return 0;
}

int pthread_cond_wait_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_wait(*cnd, *mtx);
}

int pthread_cond_timedwait_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx, const struct timespec *t) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_timedwait(*cnd, *mtx, t);
}

int clock_gettime_hook(int clk_id, struct timespec *t) {
	struct timeval now;
	int rv = gettimeofday(&now, NULL);
	if (rv)
		return rv;
	t->tv_sec = now.tv_sec;
	t->tv_nsec = now.tv_usec * 1000;

	return 0;
}

int pthread_cond_timedwait_relative_np_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx, struct timespec *ts) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	
	if (ts != NULL) {
		struct timespec ct;
		clock_gettime_hook(0, &ct);
		ts->tv_sec += ct.tv_sec;
		ts->tv_nsec += ct.tv_nsec;
	}
	
	pthread_cond_timedwait(*cnd, *mtx, ts); // FIXME
	return 0;
}

int pthread_create_fake(pthread_t *thread, const void *unused, void *entry, void *arg) {
	return pthread_create(thread, NULL, entry, arg);
}

int pthread_once_fake(volatile int *once_control, void (*init_routine)(void)) {
	if (!once_control || !init_routine)
		return -1;
	if (__sync_lock_test_and_set(once_control, 1) == 0)
		(*init_routine)();
	return 0;
}

int GetCurrentThreadId(void) {
	return sceKernelGetThreadId();
}

extern void *__aeabi_ldiv0;

int GetEnv(void *vm, void **env, int r2) {
	*env = fake_env;
	return 0;
}

extern void *__aeabi_atexit;
extern void *__aeabi_idiv;
extern void *__aeabi_idivmod;
extern void *__aeabi_ldivmod;
extern void *__aeabi_uidiv;
extern void *__aeabi_uidivmod;
extern void *__aeabi_uldivmod;
extern void *__cxa_atexit;
extern void *__cxa_finalize;
extern void *__cxa_call_unexpected;
extern void *__gnu_unwind_frame;
extern void *__stack_chk_fail;
int open(const char *pathname, int flags);

static int __stack_chk_guard_fake = 0x42424242;

static FILE __sF_fake[0x1000][3];

int stat_hook(const char *pathname, void *statbuf) {
	//dlog("stat(%s)\n", pathname);
	struct stat st;
	int res = stat(pathname, &st);
	if (res == 0)
		*(uint64_t *)(statbuf + 0x30) = st.st_size;
	return res;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	return memalign(length, 0x1000);
}

int munmap(void *addr, size_t length) {
	free(addr);
	return 0;
}

int fstat_hook(int fd, void *statbuf) {
	struct stat st;
	int res = fstat(fd, &st);
	if (res == 0)
		*(uint64_t *)(statbuf + 0x30) = st.st_size;
	return res;
}

extern void *__cxa_guard_acquire;
extern void *__cxa_guard_release;

char *basename(char *path) {
	char *p = path;
	if (strlen(path) == 1)
		return path;
	char *slash = strstr(p, "/");
	while (slash) {
		p = slash + 1;
		slash = strstr(p, "/");
	}
	return p;
}

void *sceClibMemclr(void *dst, SceSize len) {
	return sceClibMemset(dst, 0, len);
}

void *sceClibMemset2(void *dst, SceSize len, int ch) {
	return sceClibMemset(dst, ch, len);
}

void *Android_JNI_GetEnv() {
	return fake_env;
}

char *SDL_AndroidGetExternalStoragePath() {
	return DATA_PATH;
}

char *SDL_AndroidGetInternalStoragePath() {
	return DATA_PATH;
}

char *SDL_GetBasePath_hook() {
	char *r = (char *)SDL_malloc(512);
	sprintf(r, "%s/assets/", DATA_PATH);
	return r;
}

int g_SDL_BufferGeometry_w;
int g_SDL_BufferGeometry_h;

void abort_hook() {
	//dlog("ABORT CALLED!!!\n");
	uint8_t *p = NULL;
	p[0] = 1;
}

int ret99() {
	return 99;
}

int chdir_hook(const char *path) {
	return 0;
}

void glShaderSource_fake(GLuint shader, GLsizei count, const GLchar **string, const GLint *length) {
	//dlog("Shader with count %d\n", count);
	
	uint32_t sha1[5];
	SHA1_CTX ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, *string, length ? *length : strlen(*string));
	sha1_final(&ctx, (uint8_t *)sha1);
	
	char sha_name[64];
	snprintf(sha_name, sizeof(sha_name), "%08x%08x%08x%08x%08x", sha1[0], sha1[1], sha1[2], sha1[3], sha1[4]);
	char gxp_path[128], glsl_path[128];
	snprintf(gxp_path, sizeof(gxp_path), "%s/%s.gxp", "ux0:data/tombraider", sha_name);
	
	FILE *file = fopen(gxp_path, "rb");
	if (!file) {
		snprintf(gxp_path, sizeof(gxp_path), "%s/%s.glsl", "ux0:data/tombraider", sha_name);
		printf("Dumping shader %s\n", gxp_path);
		file = fopen(gxp_path, "wb");
		fwrite(*string, 1, length ? *length : strlen(*string), file);
		fclose(file);
	} else {
		size_t shaderSize;
		void *shaderBuf;

		fseek(file, 0, SEEK_END);
		shaderSize = ftell(file);
		fseek(file, 0, SEEK_SET);

		shaderBuf = vglMalloc(shaderSize);
		fread(shaderBuf, 1, shaderSize, file);
		fclose(file);

		glShaderBinary(1, &shader, 0, shaderBuf, shaderSize);

		vglFree(shaderBuf);
	}
}

static so_default_dynlib gl_hook[] = {
	{"glShaderSource", (uintptr_t)&glShaderSource_fake},
	{"glCompileShader", (uintptr_t)&ret0},
};
static size_t gl_numhook = sizeof(gl_hook) / sizeof(*gl_hook);

void *SDL_GL_GetProcAddress_fake(const char *symbol) {
	dlog("looking for symbol %s\n", symbol);
	for (size_t i = 0; i < gl_numhook; ++i) {
		if (!strcmp(symbol, gl_hook[i].symbol)) {
			return (void *)gl_hook[i].func;
		}
	}
	void *r = vglGetProcAddress(symbol);
	if (!r) {
		dlog("Cannot find symbol %s\n", symbol);
	}
	return r;
}

#define SCE_ERRNO_MASK 0xFF

#define DT_DIR 4
#define DT_REG 8

struct android_dirent {
	char pad[18];
	unsigned char d_type;
	char d_name[256];
};

typedef struct {
	SceUID uid;
	struct android_dirent dir;
} android_DIR;

int closedir_fake(android_DIR *dirp) {
	if (!dirp || dirp->uid < 0) {
		errno = EBADF;
		return -1;
	}

	int res = sceIoDclose(dirp->uid);
	dirp->uid = -1;

	free(dirp);

	if (res < 0) {
		errno = res & SCE_ERRNO_MASK;
		return -1;
	}

	errno = 0;
	return 0;
}

android_DIR *opendir_fake(const char *dirname) {
	//dlog("opendir(%s)\n", dirname);
	SceUID uid = sceIoDopen(dirname);

	if (uid < 0) {
		errno = uid & SCE_ERRNO_MASK;
		return NULL;
	}

	android_DIR *dirp = calloc(1, sizeof(android_DIR));

	if (!dirp) {
		sceIoDclose(uid);
		errno = ENOMEM;
		return NULL;
	}

	dirp->uid = uid;

	errno = 0;
	return dirp;
}

struct android_dirent *readdir_fake(android_DIR *dirp) {
	if (!dirp) {
		errno = EBADF;
		return NULL;
	}

	SceIoDirent sce_dir;
	int res = sceIoDread(dirp->uid, &sce_dir);

	if (res < 0) {
		errno = res & SCE_ERRNO_MASK;
		return NULL;
	}

	if (res == 0) {
		errno = 0;
		return NULL;
	}

	dirp->dir.d_type = SCE_S_ISDIR(sce_dir.d_stat.st_mode) ? DT_DIR : DT_REG;
	strcpy(dirp->dir.d_name, sce_dir.d_name);
	return &dirp->dir;
}

SDL_Surface *IMG_Load_hook(const char *file) {
	char real_fname[256];
	//printf("loading %s\n", file);
	if (strncmp(file, "ux0:", 4)) {
		sprintf(real_fname, "%s/assets/%s", DATA_PATH, file);
		return IMG_Load(real_fname);
	}
	return IMG_Load(file);
}

SDL_Texture * IMG_LoadTexture_hook(SDL_Renderer *renderer, const char *file) {
	char real_fname[256];
	//printf("loading %s\n", file);
	if (strncmp(file, "ux0:", 4)) {
		sprintf(real_fname, "%s/assets/%s", DATA_PATH, file);
		return IMG_LoadTexture(renderer, real_fname);
	}
	return IMG_LoadTexture(renderer, file);
}

SDL_RWops *SDL_RWFromFile_hook(const char *fname, const char *mode) {
	SDL_RWops *f;
	char real_fname[256];
	//printf("SDL_RWFromFile(%s,%s)\n", fname, mode);
	if (strncmp(fname, "ux0:", 4)) {
		sprintf(real_fname, "%s/assets/%s", DATA_PATH, fname);
		//printf("SDL_RWFromFile patched to %s\n", real_fname);
		f = SDL_RWFromFile(real_fname, mode);
	} else {
		f = SDL_RWFromFile(fname, mode);
	}
	return f;
}

FILE *fopen_hook(char *fname, char *mode) {
	FILE *f;
	char real_fname[256];
	//printf("fopen(%s,%s)\n", fname, mode);
	if (strncmp(fname, "ux0:", 4)) {
		sprintf(real_fname, "%s/%s", DATA_PATH, fname);
		f = fopen(real_fname, mode);
	} else {
		f = fopen(fname, mode);
	}
	return f;
}

SDL_GLContext SDL_GL_CreateContext_fake(SDL_Window * window) {
	eglSwapInterval(0, force_30fps ? 2 : 1);
	return SDL_GL_CreateContext(window);
}

SDL_Window * SDL_CreateWindow_fake(const char *title, int x, int y, int w, int h, Uint32 flags) {
	return SDL_CreateWindow(title, 0, 0, SCREEN_W, SCREEN_H, flags);
}

SDL_Renderer *SDL_CreateRenderer_hook(SDL_Window *window, int index, Uint32 flags) {
	SDL_Renderer *r = SDL_CreateRenderer(window, index, flags);
	SDL_RenderSetLogicalSize(r, SCREEN_W, SCREEN_H);
	return r;
}

int SDL_Init_fake(Uint32 flags) {
	int r = SDL_Init(flags);
	Mix_OpenAudio(44100, AUDIO_S16SYS, 2, 1024);
	Mix_AllocateChannels(52);
	return r;
}

extern void *_Znaj;
extern void *_ZdlPv;
extern void *_Znwj;

static so_default_dynlib default_dynlib[] = {
	{ "opendir", (uintptr_t)&opendir_fake },
	{ "readdir", (uintptr_t)&readdir_fake },
	{ "closedir", (uintptr_t)&closedir_fake },
	{ "g_SDL_BufferGeometry_w", (uintptr_t)&g_SDL_BufferGeometry_w },
	{ "g_SDL_BufferGeometry_h", (uintptr_t)&g_SDL_BufferGeometry_h },
	{ "SL_IID_BUFFERQUEUE", (uintptr_t)&SL_IID_BUFFERQUEUE },
	{ "SL_IID_ENGINE", (uintptr_t)&SL_IID_ENGINE },
	{ "SL_IID_EFFECTSEND", (uintptr_t)&SL_IID_EFFECTSEND },
	{ "SL_IID_ENVIRONMENTALREVERB", (uintptr_t)&SL_IID_ENVIRONMENTALREVERB },
	{ "SL_IID_PLAY", (uintptr_t)&SL_IID_PLAY },
	{ "SL_IID_PLAYBACKRATE", (uintptr_t)&SL_IID_PLAYBACKRATE },
	{ "SL_IID_SEEK", (uintptr_t)&SL_IID_SEEK },
	{ "SL_IID_VOLUME", (uintptr_t)&SL_IID_VOLUME },
	{ "slCreateEngine", (uintptr_t)&slCreateEngine },
	{ "__aeabi_memclr", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memclr4", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memclr8", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memcpy4", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memcpy8", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memmove4", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memmove8", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memcpy", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memmove", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memset", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_memset4", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_memset8", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_atexit", (uintptr_t)&__aeabi_atexit },
	{ "__android_log_print", (uintptr_t)&__android_log_print },
	{ "__android_log_vprint", (uintptr_t)&__android_log_vprint },
	{ "__android_log_write", (uintptr_t)&__android_log_write },
	{ "__cxa_atexit", (uintptr_t)&__cxa_atexit },
	{ "__cxa_call_unexpected", (uintptr_t)&__cxa_call_unexpected },
	{ "__cxa_guard_acquire", (uintptr_t)&__cxa_guard_acquire },
	{ "__cxa_guard_release", (uintptr_t)&__cxa_guard_release },
	{ "__cxa_finalize", (uintptr_t)&__cxa_finalize },
	{ "__errno", (uintptr_t)&__errno },
	{ "__gnu_unwind_frame", (uintptr_t)&__gnu_unwind_frame },
	{ "__gnu_Unwind_Find_exidx", (uintptr_t)&ret0 },
	{ "dl_unwind_find_exidx", (uintptr_t)&ret0 },
	// { "__google_potentially_blocking_region_begin", (uintptr_t)&__google_potentially_blocking_region_begin },
	// { "__google_potentially_blocking_region_end", (uintptr_t)&__google_potentially_blocking_region_end },
	{ "__sF", (uintptr_t)&__sF_fake },
	{ "__stack_chk_fail", (uintptr_t)&__stack_chk_fail },
	{ "__stack_chk_guard", (uintptr_t)&__stack_chk_guard_fake },
	{ "_ctype_", (uintptr_t)&BIONIC_ctype_},
	{ "_tolower_tab_", (uintptr_t)&BIONIC_tolower_tab_},
	{ "_toupper_tab_", (uintptr_t)&BIONIC_toupper_tab_},
	{ "abort", (uintptr_t)&abort_hook },
	{ "access", (uintptr_t)&access },
	{ "acos", (uintptr_t)&acos },
	{ "acosh", (uintptr_t)&acosh },
	{ "asctime", (uintptr_t)&asctime },
	{ "acosf", (uintptr_t)&acosf },
	{ "asin", (uintptr_t)&asin },
	{ "asinh", (uintptr_t)&asinh },
	{ "asinf", (uintptr_t)&asinf },
	{ "atan", (uintptr_t)&atan },
	{ "atanh", (uintptr_t)&atanh },
	{ "atan2", (uintptr_t)&atan2 },
	{ "atan2f", (uintptr_t)&atan2f },
	{ "atanf", (uintptr_t)&atanf },
	{ "atoi", (uintptr_t)&atoi },
	{ "atol", (uintptr_t)&atol },
	{ "atoll", (uintptr_t)&atoll },
	{ "basename", (uintptr_t)&basename },
	// { "bind", (uintptr_t)&bind },
	{ "bsearch", (uintptr_t)&bsearch },
	{ "btowc", (uintptr_t)&btowc },
	{ "calloc", (uintptr_t)&calloc },
	{ "ceil", (uintptr_t)&ceil },
	{ "ceilf", (uintptr_t)&ceilf },
	{ "chdir", (uintptr_t)&chdir_hook },
	{ "clearerr", (uintptr_t)&clearerr },
	{ "clock", (uintptr_t)&clock },
	{ "clock_gettime", (uintptr_t)&clock_gettime_hook },
	{ "close", (uintptr_t)&close },
	{ "cos", (uintptr_t)&cos },
	{ "cosf", (uintptr_t)&cosf },
	{ "cosh", (uintptr_t)&cosh },
	{ "crc32", (uintptr_t)&crc32 },
	{ "deflate", (uintptr_t)&deflate },
	{ "deflateEnd", (uintptr_t)&deflateEnd },
	{ "deflateInit_", (uintptr_t)&deflateInit_ },
	{ "deflateInit2_", (uintptr_t)&deflateInit2_ },
	{ "deflateReset", (uintptr_t)&deflateReset },
	{ "dlopen", (uintptr_t)&ret0 },
	// { "dlsym", (uintptr_t)&dlsym_hook },
	{ "exit", (uintptr_t)&exit },
	{ "exp", (uintptr_t)&exp },
	{ "exp2", (uintptr_t)&exp2 },
	{ "expf", (uintptr_t)&expf },
	{ "fabsf", (uintptr_t)&fabsf },
	{ "fclose", (uintptr_t)&fclose },
	{ "fcntl", (uintptr_t)&ret0 },
	// { "fdopen", (uintptr_t)&fdopen },
	{ "ferror", (uintptr_t)&ferror },
	{ "fflush", (uintptr_t)&fflush },
	{ "fgetpos", (uintptr_t)&fgetpos },
	{ "fsetpos", (uintptr_t)&fsetpos },
	{ "floor", (uintptr_t)&floor },
	{ "floorf", (uintptr_t)&floorf },
	{ "fmod", (uintptr_t)&fmod },
	{ "fmodf", (uintptr_t)&fmodf },
	{ "fopen", (uintptr_t)&fopen_hook },
	{ "fprintf", (uintptr_t)&fprintf },
	{ "fputc", (uintptr_t)&fputc },
	// { "fputwc", (uintptr_t)&fputwc },
	// { "fputs", (uintptr_t)&fputs },
	{ "fread", (uintptr_t)&fread },
	{ "free", (uintptr_t)&free },
	{ "frexp", (uintptr_t)&frexp },
	{ "frexpf", (uintptr_t)&frexpf },
	// { "fscanf", (uintptr_t)&fscanf },
	{ "fseek", (uintptr_t)&fseek },
	{ "fseeko", (uintptr_t)&fseeko },
	{ "fstat", (uintptr_t)&fstat },
	{ "ftell", (uintptr_t)&ftell },
	{ "ftello", (uintptr_t)&ftello },
	// { "ftruncate", (uintptr_t)&ftruncate },
	{ "fwrite", (uintptr_t)&fwrite },
	{ "getc", (uintptr_t)&getc },
	{ "getpid", (uintptr_t)&ret0 },
	{ "getcwd", (uintptr_t)&getcwd_hook },
	{ "getenv", (uintptr_t)&ret0 },
	{ "getwc", (uintptr_t)&getwc },
	{ "gettimeofday", (uintptr_t)&gettimeofday },
	{ "gzopen", (uintptr_t)&gzopen },
	{ "inflate", (uintptr_t)&inflate },
	{ "inflateEnd", (uintptr_t)&inflateEnd },
	{ "inflateInit_", (uintptr_t)&inflateInit_ },
	{ "inflateInit2_", (uintptr_t)&inflateInit2_ },
	{ "inflateReset", (uintptr_t)&inflateReset },
	{ "isalnum", (uintptr_t)&isalnum },
	{ "isalpha", (uintptr_t)&isalpha },
	{ "iscntrl", (uintptr_t)&iscntrl },
	{ "isdigit", (uintptr_t)&isdigit },
	{ "islower", (uintptr_t)&islower },
	{ "ispunct", (uintptr_t)&ispunct },
	{ "isprint", (uintptr_t)&isprint },
	{ "isspace", (uintptr_t)&isspace },
	{ "isupper", (uintptr_t)&isupper },
	{ "iswalpha", (uintptr_t)&iswalpha },
	{ "iswcntrl", (uintptr_t)&iswcntrl },
	{ "iswctype", (uintptr_t)&iswctype },
	{ "iswdigit", (uintptr_t)&iswdigit },
	{ "iswdigit", (uintptr_t)&iswdigit },
	{ "iswlower", (uintptr_t)&iswlower },
	{ "iswprint", (uintptr_t)&iswprint },
	{ "iswpunct", (uintptr_t)&iswpunct },
	{ "iswspace", (uintptr_t)&iswspace },
	{ "iswupper", (uintptr_t)&iswupper },
	{ "iswxdigit", (uintptr_t)&iswxdigit },
	{ "isxdigit", (uintptr_t)&isxdigit },
	{ "ldexp", (uintptr_t)&ldexp },
	{ "ldexpf", (uintptr_t)&ldexpf },
	// { "listen", (uintptr_t)&listen },
	{ "localtime", (uintptr_t)&localtime },
	{ "localtime_r", (uintptr_t)&localtime_r },
	{ "log", (uintptr_t)&log },
	{ "logf", (uintptr_t)&logf },
	{ "log10", (uintptr_t)&log10 },
	{ "log10f", (uintptr_t)&log10f },
	{ "longjmp", (uintptr_t)&longjmp },
	{ "lrand48", (uintptr_t)&lrand48 },
	{ "lrint", (uintptr_t)&lrint },
	{ "lrintf", (uintptr_t)&lrintf },
	{ "lseek", (uintptr_t)&lseek },
	{ "malloc", (uintptr_t)&malloc },
	{ "mbrtowc", (uintptr_t)&mbrtowc },
	{ "memalign", (uintptr_t)&memalign },
	{ "memchr", (uintptr_t)&sceClibMemchr },
	{ "memcmp", (uintptr_t)&sceClibMemcmp },
	{ "memcpy", (uintptr_t)&sceClibMemcpy },
	{ "memmove", (uintptr_t)&sceClibMemmove },
	{ "memset", (uintptr_t)&sceClibMemset },
	{ "mkdir", (uintptr_t)&mkdir },
	// { "mmap", (uintptr_t)&mmap},
	// { "munmap", (uintptr_t)&munmap},
	{ "modf", (uintptr_t)&modf },
	{ "modff", (uintptr_t)&modff },
	// { "poll", (uintptr_t)&poll },
	// { "open", (uintptr_t)&open },
	{ "pow", (uintptr_t)&pow },
	{ "powf", (uintptr_t)&powf },
	{ "printf", (uintptr_t)&printf },
	{ "pthread_attr_destroy", (uintptr_t)&ret0 },
	{ "pthread_attr_init", (uintptr_t)&ret0 },
	{ "pthread_attr_setdetachstate", (uintptr_t)&ret0 },
	{ "pthread_attr_setstacksize", (uintptr_t)&ret0 },
	{ "pthread_cond_init", (uintptr_t)&pthread_cond_init_fake},
	{ "pthread_cond_broadcast", (uintptr_t)&pthread_cond_broadcast_fake},
	{ "pthread_cond_wait", (uintptr_t)&pthread_cond_wait_fake},
	{ "pthread_cond_destroy", (uintptr_t)&pthread_cond_destroy_fake},
	{ "pthread_cond_timedwait", (uintptr_t)&pthread_cond_timedwait_fake},
	{ "pthread_cond_timedwait_relative_np", (uintptr_t)&pthread_cond_timedwait_relative_np_fake}, // FIXME
	{ "pthread_create", (uintptr_t)&pthread_create_fake },
	{ "pthread_getschedparam", (uintptr_t)&pthread_getschedparam },
	{ "pthread_getspecific", (uintptr_t)&pthread_getspecific },
	{ "pthread_key_create", (uintptr_t)&pthread_key_create },
	{ "pthread_key_delete", (uintptr_t)&pthread_key_delete },
	{ "pthread_mutex_destroy", (uintptr_t)&pthread_mutex_destroy_fake },
	{ "pthread_mutex_init", (uintptr_t)&pthread_mutex_init_fake },
	{ "pthread_mutex_trylock", (uintptr_t)&pthread_mutex_trylock_fake },
	{ "pthread_mutex_lock", (uintptr_t)&pthread_mutex_lock_fake },
	{ "pthread_mutex_unlock", (uintptr_t)&pthread_mutex_unlock_fake },
	{ "pthread_mutexattr_destroy", (uintptr_t)&pthread_mutexattr_destroy},
	{ "pthread_mutexattr_init", (uintptr_t)&pthread_mutexattr_init},
	{ "pthread_mutexattr_settype", (uintptr_t)&pthread_mutexattr_settype},
	{ "pthread_once", (uintptr_t)&pthread_once_fake },
	{ "pthread_self", (uintptr_t)&pthread_self },
	{ "pthread_setname_np", (uintptr_t)&ret0 },
	{ "pthread_getschedparam", (uintptr_t)&pthread_getschedparam },
	{ "pthread_setschedparam", (uintptr_t)&pthread_setschedparam },
	{ "pthread_setspecific", (uintptr_t)&pthread_setspecific },
	{ "sched_get_priority_min", (uintptr_t)&ret0 },
	{ "sched_get_priority_max", (uintptr_t)&ret99 },
	{ "putc", (uintptr_t)&putc },
	{ "puts", (uintptr_t)&puts },
	{ "putwc", (uintptr_t)&putwc },
	{ "qsort", (uintptr_t)&qsort },
	{ "rand", (uintptr_t)&rand },
	{ "read", (uintptr_t)&read },
	{ "realpath", (uintptr_t)&realpath },
	{ "realloc", (uintptr_t)&realloc },
	{ "rename", (uintptr_t)&rename },
	{ "remove", (uintptr_t)&remove },
	// { "recv", (uintptr_t)&recv },
	{ "roundf", (uintptr_t)&roundf },
	{ "rint", (uintptr_t)&rint },
	{ "rintf", (uintptr_t)&rintf },
	// { "send", (uintptr_t)&send },
	// { "sendto", (uintptr_t)&sendto },
	{ "setenv", (uintptr_t)&ret0 },
	{ "setjmp", (uintptr_t)&setjmp },
	{ "setlocale", (uintptr_t)&ret0 },
	// { "setsockopt", (uintptr_t)&setsockopt },
	{ "setvbuf", (uintptr_t)&setvbuf },
	{ "sin", (uintptr_t)&sin },
	{ "sinf", (uintptr_t)&sinf },
	{ "sinh", (uintptr_t)&sinh },
	//{ "sincos", (uintptr_t)&sincos },
	{ "snprintf", (uintptr_t)&snprintf },
	// { "socket", (uintptr_t)&socket },
	{ "sprintf", (uintptr_t)&sprintf },
	{ "sqrt", (uintptr_t)&sqrt },
	{ "sqrtf", (uintptr_t)&sqrtf },
	{ "srand", (uintptr_t)&srand },
	{ "srand48", (uintptr_t)&srand48 },
	{ "sscanf", (uintptr_t)&sscanf },
	{ "stat", (uintptr_t)&stat_hook },
	{ "strcasecmp", (uintptr_t)&strcasecmp },
	{ "strcasestr", (uintptr_t)&strstr },
	{ "strcat", (uintptr_t)&strcat },
	{ "strlcat", (uintptr_t)&strlcat },
	{ "strchr", (uintptr_t)&strchr },
	{ "strcmp", (uintptr_t)&sceClibStrcmp },
	{ "strcoll", (uintptr_t)&strcoll },
	{ "strcpy", (uintptr_t)&strcpy },
	{ "strcspn", (uintptr_t)&strcspn },
	{ "strdup", (uintptr_t)&strdup },
	{ "strerror", (uintptr_t)&strerror },
	{ "strftime", (uintptr_t)&strftime },
	{ "strlcpy", (uintptr_t)&strlcpy },
	{ "strlen", (uintptr_t)&strlen },
	{ "strncasecmp", (uintptr_t)&sceClibStrncasecmp },
	{ "strncat", (uintptr_t)&sceClibStrncat },
	{ "strncmp", (uintptr_t)&sceClibStrncmp },
	{ "strncpy", (uintptr_t)&sceClibStrncpy },
	{ "strpbrk", (uintptr_t)&strpbrk },
	{ "strrchr", (uintptr_t)&sceClibStrrchr },
	{ "strstr", (uintptr_t)&sceClibStrstr },
	{ "strtod", (uintptr_t)&strtod },
	{ "strtol", (uintptr_t)&strtol },
	{ "strtoul", (uintptr_t)&strtoul },
	{ "strtoll", (uintptr_t)&strtoll },
	{ "strtoull", (uintptr_t)&strtoull },
	{ "strxfrm", (uintptr_t)&strxfrm },
	{ "sysconf", (uintptr_t)&ret0 },
	{ "tan", (uintptr_t)&tan },
	{ "tanf", (uintptr_t)&tanf },
	{ "tanh", (uintptr_t)&tanh },
	{ "time", (uintptr_t)&time },
	{ "tolower", (uintptr_t)&tolower },
	{ "toupper", (uintptr_t)&toupper },
	{ "towlower", (uintptr_t)&towlower },
	{ "towupper", (uintptr_t)&towupper },
	{ "ungetc", (uintptr_t)&ungetc },
	{ "ungetwc", (uintptr_t)&ungetwc },
	{ "usleep", (uintptr_t)&usleep },
	{ "vfprintf", (uintptr_t)&vfprintf },
	{ "vprintf", (uintptr_t)&vprintf },
	{ "vsnprintf", (uintptr_t)&vsnprintf },
	{ "vsprintf", (uintptr_t)&vsprintf },
	{ "vswprintf", (uintptr_t)&vswprintf },
	{ "wcrtomb", (uintptr_t)&wcrtomb },
	{ "wcscoll", (uintptr_t)&wcscoll },
	{ "wcscmp", (uintptr_t)&wcscmp },
	{ "wcsncpy", (uintptr_t)&wcsncpy },
	{ "wcsftime", (uintptr_t)&wcsftime },
	{ "wcslen", (uintptr_t)&wcslen },
	{ "wcsxfrm", (uintptr_t)&wcsxfrm },
	{ "wctob", (uintptr_t)&wctob },
	{ "wctype", (uintptr_t)&wctype },
	{ "wmemchr", (uintptr_t)&wmemchr },
	{ "wmemcmp", (uintptr_t)&wmemcmp },
	{ "wmemcpy", (uintptr_t)&wmemcpy },
	{ "wmemmove", (uintptr_t)&wmemmove },
	{ "wmemset", (uintptr_t)&wmemset },
	{ "write", (uintptr_t)&write },
	// { "writev", (uintptr_t)&writev },
	{ "glClearColor", (uintptr_t)&glClearColor },
	{ "glClearDepthf", (uintptr_t)&glClearDepthf },
	{ "glTexSubImage2D", (uintptr_t)&glTexSubImage2D },
	{ "glTexImage2D", (uintptr_t)&glTexImage2D },
	{ "glDeleteTextures", (uintptr_t)&glDeleteTextures },
	{ "glDepthFunc", (uintptr_t)&glDepthFunc },
	{ "glGenTextures", (uintptr_t)&glGenTextures },
	{ "glBindTexture", (uintptr_t)&glBindTexture },
	{ "glTexParameteri", (uintptr_t)&glTexParameteri },
	{ "glGetError", (uintptr_t)&glGetError },
	{ "glMatrixMode", (uintptr_t)&glMatrixMode },
	{ "glLoadIdentity", (uintptr_t)&glLoadIdentity },
	{ "glScalef", (uintptr_t)&glScalef },
	{ "glClear", (uintptr_t)&glClear },
	{ "glOrthof", (uintptr_t)&glOrthof },
	{ "glViewport", (uintptr_t)&glViewport },
	{ "glScissor", (uintptr_t)&glScissor },
	{ "glEnable", (uintptr_t)&glEnable },
	{ "glDisable", (uintptr_t)&glDisable },
	{ "glUniform3fv", (uintptr_t)&glUniform3fv},
	{ "glUniform2f", (uintptr_t)&glUniform2f},
	{ "glUniform1f", (uintptr_t)&glUniform1f},
	{ "glUniform4f", (uintptr_t)&glUniform4f},
	{ "glUniform4fv", (uintptr_t)&glUniform4fv},
	{ "glIsTexture", (uintptr_t)&glIsTexture},
	{ "glIsRenderbuffer", (uintptr_t)&ret0},
	{ "glBindRenderbuffer", (uintptr_t)&glBindRenderbuffer},
	{ "glGetRenderbufferParameteriv", (uintptr_t)&ret0},
	{ "glDeleteFramebuffers", (uintptr_t)&glDeleteFramebuffers},
	{ "glGenFramebuffers", (uintptr_t)&glGenFramebuffers},
	{ "glGenRenderbuffers", (uintptr_t)&glGenRenderbuffers},
	{ "glFramebufferRenderbuffer", (uintptr_t)&glFramebufferRenderbuffer},
	{ "glFramebufferTexture2D", (uintptr_t)&glFramebufferTexture2D},
	{ "glRenderbufferStorage", (uintptr_t)&glRenderbufferStorage},
	{ "glCheckFramebufferStatus", (uintptr_t)&glCheckFramebufferStatus},
	{ "glDeleteBuffers", (uintptr_t)&glDeleteBuffers},
	{ "glGenBuffers", (uintptr_t)&glGenBuffers},
	{ "glBufferSubData", (uintptr_t)&glBufferSubData},
	{ "glBufferData", (uintptr_t)&glBufferData},
	{ "glLineWidth", (uintptr_t)&glLineWidth},
	{ "_Znwj", (uintptr_t)&_Znwj},
	{ "glCreateProgram", (uintptr_t)&glCreateProgram},
	{ "glAttachShader", (uintptr_t)&glAttachShader},
	{ "glBindAttribLocation", (uintptr_t)&glBindAttribLocation},
	{ "glLinkProgram", (uintptr_t)&glLinkProgram},
	{ "glGetProgramiv", (uintptr_t)&glGetProgramiv},
	{ "glGetFramebufferAttachmentParameteriv", (uintptr_t)&glGetFramebufferAttachmentParameteriv},
	{ "glGetUniformLocation", (uintptr_t)&glGetUniformLocation},
	{ "glUseProgram", (uintptr_t)&glUseProgram},
	{ "glUniformMatrix4fv", (uintptr_t)&glUniformMatrix4fv},
	{ "glGetProgramInfoLog", (uintptr_t)&glGetProgramInfoLog},
	{ "glDeleteProgram", (uintptr_t)&glDeleteProgram},
	{ "glEnableVertexAttribArray", (uintptr_t)&glEnableVertexAttribArray},
	{ "glDepthMask", (uintptr_t)&glDepthMask},
	{ "glGetIntegerv", (uintptr_t)&glGetIntegerv},
	{ "glUniform1i", (uintptr_t)&glUniform1i},
	{ "glBindFramebuffer", (uintptr_t)&glBindFramebuffer},
	{ "glActiveTexture", (uintptr_t)&glActiveTexture},
	{ "glTexParameterf", (uintptr_t)&glTexParameterf},
	{ "glPixelStorei", (uintptr_t)&ret0},
	{ "glCompressedTexImage2D", (uintptr_t)&glCompressedTexImage2D},
	{ "glGenerateMipmap", (uintptr_t)&glGenerateMipmap},
	{ "_ZdlPv", (uintptr_t)&_ZdlPv},
	{ "glGetString", (uintptr_t)&glGetString},
	{ "glGetFloatv", (uintptr_t)&glGetFloatv},
	{ "glBindBuffer", (uintptr_t)&glBindBuffer},
	{ "glVertexAttribPointer", (uintptr_t)&glVertexAttribPointer},
	{ "glDrawArrays", (uintptr_t)&glDrawArrays},
	{ "glCreateShader", (uintptr_t)&glCreateShader},
	{ "glShaderSource", (uintptr_t)&glShaderSource_fake},
	{ "glCompileShader", (uintptr_t)&ret0},
	{ "glGetShaderiv", (uintptr_t)&glGetShaderiv},
	{ "glGetShaderInfoLog", (uintptr_t)&glGetShaderInfoLog},
	{ "glDeleteShader", (uintptr_t)&glDeleteShader},
	{ "eglGetProcAddress", (uintptr_t)&eglGetProcAddress},
	{ "_Znaj", (uintptr_t)&_Znaj},
	{ "glEnableClientState", (uintptr_t)&glEnableClientState },
	{ "glDisableClientState", (uintptr_t)&glDisableClientState },
	{ "glBlendFunc", (uintptr_t)&glBlendFunc },
	{ "glColorPointer", (uintptr_t)&glColorPointer },
	{ "glVertexPointer", (uintptr_t)&glVertexPointer },
	{ "glTexCoordPointer", (uintptr_t)&glTexCoordPointer },
	{ "glDrawElements", (uintptr_t)&glDrawElements },
	{ "Android_JNI_GetEnv", (uintptr_t)&Android_JNI_GetEnv },
	{ "IMG_Load", (uintptr_t)&IMG_Load_hook },
	{ "IMG_LoadTexture", (uintptr_t)&IMG_LoadTexture_hook },
	{ "IMG_LoadTexture_RW", (uintptr_t)&IMG_LoadTexture_RW },
	{ "raise", (uintptr_t)&raise },
};
static size_t numhooks = sizeof(default_dynlib) / sizeof(*default_dynlib);

int check_kubridge(void) {
	int search_unk[2];
	return _vshKernelSearchModuleByName("kubridge", search_unk);
}

enum MethodIDs {
	UNKNOWN = 0,
	INIT,
} MethodIDs;

typedef struct {
	char *name;
	enum MethodIDs id;
} NameToMethodID;

static NameToMethodID name_to_method_ids[] = {
	{ "<init>", INIT },
};

int GetMethodID(void *env, void *class, const char *name, const char *sig) {
	printf("GetMethodID: %s\n", name);

	for (int i = 0; i < sizeof(name_to_method_ids) / sizeof(NameToMethodID); i++) {
		if (strcmp(name, name_to_method_ids[i].name) == 0) {
			return name_to_method_ids[i].id;
		}
	}

	return UNKNOWN;
}

int GetStaticMethodID(void *env, void *class, const char *name, const char *sig) {
	//printf("GetStaticMethodID: %s\n", name);
	
	for (int i = 0; i < sizeof(name_to_method_ids) / sizeof(NameToMethodID); i++) {
		if (strcmp(name, name_to_method_ids[i].name) == 0)
			return name_to_method_ids[i].id;
	}

	return UNKNOWN;
}

void CallStaticVoidMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
}

int CallStaticBooleanMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		return 0;
	}
}

int CallStaticIntMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		return 0;	
	}
}

int64_t CallStaticLongMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		return 0;	
	}
}

uint64_t CallLongMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	return -1;
}

void *FindClass(void) {
	return (void *)0x41414141;
}

void *NewGlobalRef(void *env, char *str) {
	return (void *)0x42424242;
}

void DeleteGlobalRef(void *env, char *str) {
}

void *NewObjectV(void *env, void *clazz, int methodID, uintptr_t args) {
	return (void *)0x43434343;
}

void *GetObjectClass(void *env, void *obj) {
	return (void *)0x44444444;
}

char *NewStringUTF(void *env, char *bytes) {
	return bytes;
}

char *GetStringUTFChars(void *env, char *string, int *isCopy) {
	return string;
}

size_t GetStringUTFLength(void *env, char *string) {
	return strlen(string);	
}

int GetJavaVM(void *env, void **vm) {
	*vm = fake_vm;
	return 0;
}

int GetFieldID(void *env, void *clazz, const char *name, const char *sig) {
	return 0;
}

int GetBooleanField(void *env, void *obj, int fieldID) {
	return 0;
}

void *CallObjectMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		return NULL;
	}
}

int CallBooleanMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		return 0;
	}
}

void CallVoidMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		break;
	}
}

int GetStaticFieldID(void *env, void *clazz, const char *name, const char *sig) {
	return 0;
}

void *GetStaticObjectField(void *env, void *clazz, int fieldID) {
	switch (fieldID) {
	default:
		return NULL;
	}
}

void GetStringUTFRegion(void *env, char *str, size_t start, size_t len, char *buf) {
	sceClibMemcpy(buf, &str[start], len);
	buf[len] = 0;
}

void *CallStaticObjectMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	return NULL;
}

int GetIntField(void *env, void *obj, int fieldID) { return 0; }

float GetFloatField(void *env, void *obj, int fieldID) {
	switch (fieldID) {
	default:
		return 0.0f;
	}
}

float CallStaticFloatMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		if (methodID != UNKNOWN) {
			dlog("CallStaticDoubleMethodV(%d)\n", methodID);
		}
		return 0;
	}
}

const char *S_LocalizedString(int id) {
	switch (id) {
	case 0:
		return "EN";
	case 1:
		return "\"Lara's Home\"";
	case 10:
		return "Living Quarters";
	case 100:
		return "Pistols";
	case 101:
		return "Shotgun";
	case 102:
		return "Automatic Pistols";
	case 103:
		return "Uzis";
	case 104:
		return "Harpoon Gun";
	case 105:
		return "M16";
	case 106:
		return "Grenade Launcher";
	case 107:
		return "Flare";
	case 108:
		return "Pistol Clips";
	case 109:
		return "Shotgun Shells";
	case 11:
		return "The Deck";
	case 110:
		return "Automatic Pistol Clips";
	case 111:
		return "Uzi Clips";
	case 112:
		return "Harpoons";
	case 113:
		return "M16 Clips";
	case 114:
		return "Grenades";
	case 115:
		return "Small Medi Pack";
	case 116:
		return "Large Medi Pack";
	case 117:
		return "Pickup";
	case 118:
		return "Puzzle";
	case 119:
		return "Key";
	case 12:
		return "Tibetan Foothills";
	case 120:
		return "Game";
	case 121:
		return "\"Lara's Home\"";
	case 122:
		return "LOADING";
	case 123:
		return "Time Taken";
	case 124:
		return "Secrets Found";
	case 125:
		return "Location";
	case 126:
		return "Kills";
	case 127:
		return "Ammo Used";
	case 128:
		return "Hits";
	case 129:
		return "Saves Performed";
	case 13:
		return "Barkhang Monastery";
	case 130:
		return "Distance Travelled";
	case 131:
		return "Health Packs Used";
	case 132:
		return "Release Version 1.1";
	case 133:
		return "None";
	case 134:
		return "Finish";
	case 135:
		return "BEST TIMES";
	case 136:
		return "No Times Set";
	case 137:
		return "N/A";
	case 138:
		return "Current Position";
	case 139:
		return "Final Statistics";
	case 14:
		return "Catacombs of the Talion";
	case 140:
		return "of";
	case 141:
		return "Story so far...";
	case 142:
		return "A: Select";
	case 143:
		return "B: Go Back";
	case 144:
		return "spare";
	case 145:
		return "spare";
	case 146:
		return "spare";
	case 147:
		return "spare";
	case 148:
		return "spare";
	case 149:
		return "spare";
	case 15:
		return "Ice Palace";
	case 150:
		return "spare";
	case 151:
		return "spare";
	case 152:
		return "spare";
	case 153:
		return "Detail Levels";
	case 154:
		return "Demo Mode";
	case 155:
		return "Sound";
	case 156:
		return "Controls";
	case 157:
		return "Gamma";
	case 158:
		return "Set Volumes";
	case 159:
		return "User Keys";
	case 16:
		return "Temple of Xian";
	case 160:
		return "The file could not be saved!";
	case 161:
		return "Try Again?";
	case 162:
		return "YES";
	case 163:
		return "NO";
	case 164:
		return "Save Complete!";
	case 165:
		return "No save games!";
	case 166:
		return "None valid";
	case 167:
		return "Save Game?";
	case 168:
		return "- EMPTY SLOT -";
	case 169:
		return "OFF";
	case 17:
		return "Floating Islands";
	case 170:
		return "ON";
	case 171:
		return "Setup Sound Card";
	case 172:
		return "Default Keys";
	case 173:
		return "DOZY";
	case 174:
		return "spare";
	case 175:
		return "spare";
	case 176:
		return "spare";
	case 177:
		return "spare";
	case 178:
		return "spare";
	case 179:
		return "spare";
	case 18:
		return "\"The Dragon's Lair\"";
	case 180:
		return "spare";
	case 181:
		return "spare";
	case 182:
		return "spare";
	case 183:
		return "spare";
	case 184:
		return "spare";
	case 185:
		return "spare";
	case 186:
		return "spare";
	case 187:
		return "spare";
	case 188:
		return "spare";
	case 189:
		return "spare";
	case 19:
		return "Home Sweet Home";
	case 190:
		return "spare";
	case 191:
		return "spare";
	case 192:
		return "spare";
	case 193:
		return "spare";
	case 194:
		return "P1";
	case 195:
		return "P1";
	case 196:
		return "P1";
	case 197:
		return "P1";
	case 198:
		return "Relay Box";
	case 199:
		return "P1";
	case 2:
		return "The Great Wall";
	case 20:
		return "Venice";
	case 200:
		return "Machine Chip";
	case 201:
		return "P1";
	case 202:
		return "Circuit Breaker";
	case 203:
		return "P1";
	case 204:
		return "P1";
	case 205:
		return "P1";
	case 206:
		return "Prayer Wheels";
	case 207:
		return "Tibetan Mask";
	case 208:
		return "Tibetan Mask";
	case 209:
		return "The Dragon Seal";
	case 21:
		return "Wreck of the Maria Doria";
	case 210:
		return "Mystic Plaque";
	case 211:
		return "Mystic Plaque";
	case 212:
		return "Dagger of Xian";
	case 213:
		return "P1";
	case 214:
		return "Circuit Breaker";
	case 215:
		return "P1";
	case 216:
		return "P2";
	case 217:
		return "P2";
	case 218:
		return "P2";
	case 219:
		return "P2";
	case 22:
		return "Tibetan Foothills";
	case 220:
		return "Circuit Board";
	case 221:
		return "P2";
	case 222:
		return "P2";
	case 223:
		return "P2";
	case 224:
		return "P2";
	case 225:
		return "P2";
	case 226:
		return "P2";
	case 227:
		return "P2";
	case 228:
		return "Gemstones";
	case 229:
		return "P2";
	case 23:
		return "data\\title.TR2";
	case 230:
		return "P2";
	case 231:
		return "P2";
	case 232:
		return "Mystic Plaque";
	case 233:
		return "Dagger of Xian";
	case 234:
		return "P2";
	case 235:
		return "P2";
	case 236:
		return "P2";
	case 237:
		return "P2";
	case 238:
		return "P3";
	case 239:
		return "P3";
	case 24:
		return "data\\title.pcx";
	case 240:
		return "P3";
	case 241:
		return "P3";
	case 242:
		return "P3";
	case 243:
		return "P3";
	case 244:
		return "P3";
	case 245:
		return "P3";
	case 246:
		return "P3";
	case 247:
		return "P3";
	case 248:
		return "P3";
	case 249:
		return "P3";
	case 25:
		return "data\\legal.pcx";
	case 250:
		return "P3";
	case 251:
		return "P3";
	case 252:
		return "P3";
	case 253:
		return "P3";
	case 254:
		return "P3";
	case 255:
		return "P3";
	case 256:
		return "P3";
	case 257:
		return "P3";
	case 258:
		return "P3";
	case 259:
		return "P3";
	case 26:
		return "data\\titleUS.pcx";
	case 260:
		return "P4";
	case 261:
		return "P4";
	case 262:
		return "P4";
	case 263:
		return "P4";
	case 264:
		return "P4";
	case 265:
		return "P4";
	case 266:
		return "P4";
	case 267:
		return "P4";
	case 268:
		return "P4";
	case 269:
		return "P4";
	case 27:
		return "data\\legalUS.pcx";
	case 270:
		return "The Seraph";
	case 271:
		return "The Seraph";
	case 272:
		return "The Seraph";
	case 273:
		return "P4";
	case 274:
		return "P4";
	case 275:
		return "P4";
	case 276:
		return "P4";
	case 277:
		return "P4";
	case 278:
		return "P4";
	case 279:
		return "P4";
	case 28:
		return "data\\titleJAP.pcx";
	case 280:
		return "P4";
	case 281:
		return "The Seraph";
	case 282:
		return "P1";
	case 283:
		return "P1";
	case 284:
		return "P1";
	case 285:
		return "P1";
	case 286:
		return "P1";
	case 287:
		return "P1";
	case 288:
		return "P1";
	case 289:
		return "P1";
	case 29:
		return "data\\legalJAP.pcx";
	case 290:
		return "P1";
	case 291:
		return "P1";
	case 292:
		return "P1";
	case 293:
		return "P1";
	case 294:
		return "P1";
	case 295:
		return "Gong Hammer";
	case 296:
		return "P1";
	case 297:
		return "P1";
	case 298:
		return "P1";
	case 299:
		return "P1";
	case 3:
		return "Venice";
	case 30:
		return "FMV\\LOGO.RPL";
	case 300:
		return "P1";
	case 301:
		return "P1";
	case 302:
		return "P1";
	case 303:
		return "P1";
	case 304:
		return "P2";
	case 305:
		return "P2";
	case 306:
		return "P2";
	case 307:
		return "P2";
	case 308:
		return "P2";
	case 309:
		return "P2";
	case 31:
		return "FMV\\ANCIENT.RPL";
	case 310:
		return "P2";
	case 311:
		return "P2";
	case 312:
		return "P2";
	case 313:
		return "P2";
	case 314:
		return "P2";
	case 315:
		return "P2";
	case 316:
		return "P2";
	case 317:
		return "P2";
	case 318:
		return "Talion";
	case 319:
		return "P2";
	case 32:
		return "FMV\\MODERN.RPL";
	case 320:
		return "P2";
	case 321:
		return "P2";
	case 322:
		return "P2";
	case 323:
		return "P2";
	case 324:
		return "P2";
	case 325:
		return "P2";
	case 326:
		return "K1";
	case 327:
		return "Guardhouse Key";
	case 328:
		return "Boathouse Key";
	case 329:
		return "Library Key";
	case 33:
		return "FMV\\LANDING.RPL";
	case 330:
		return "Ornate Key";
	case 331:
		return "Red Pass Card";
	case 332:
		return "Red Pass Card";
	case 333:
		return "K1";
	case 334:
		return "Rest Room Key";
	case 335:
		return "Theatre Key";
	case 336:
		return "K1";
	case 337:
		return "Drawbridge Key";
	case 338:
		return "Strongroom Key";
	case 339:
		return "K1";
	case 34:
		return "FMV\\MS.RPL";
	case 340:
		return "K1";
	case 341:
		return "K1";
	case 342:
		return "K1";
	case 343:
		return "K1";
	case 344:
		return "Gun Cupboard Key";
	case 345:
		return "Boathouse Key";
	case 346:
		return "Rest Room Key";
	case 347:
		return "Drawbridge Key";
	case 348:
		return "K2";
	case 349:
		return "Rusty Key";
	case 35:
		return "FMV\\CRASH.RPL";
	case 350:
		return "Steel Key";
	case 351:
		return "Detonator Key";
	case 352:
		return "K2";
	case 353:
		return "Yellow Pass Card";
	case 354:
		return "K2";
	case 355:
		return "K2";
	case 356:
		return "Rusty Key";
	case 357:
		return "Rusty Key";
	case 358:
		return "Stern Key";
	case 359:
		return "Hut Key";
	case 36:
		return "FMV\\JEEP.RPL";
	case 360:
		return "Trapdoor Key";
	case 361:
		return "K2";
	case 362:
		return "Gong Hammer";
	case 363:
		return "Gold Key";
	case 364:
		return "K2";
	case 365:
		return "K2";
	case 366:
		return "K2";
	case 367:
		return "Steel Key";
	case 368:
		return "Rusty Key";
	case 369:
		return "Hut Key";
	case 37:
		return "FMV\\END.RPL";
	case 370:
		return "K3";
	case 371:
		return "K3";
	case 372:
		return "Iron Key";
	case 373:
		return "K3";
	case 374:
		return "K3";
	case 375:
		return "Green Pass Card";
	case 376:
		return "K3";
	case 377:
		return "K3";
	case 378:
		return "Cabin Key";
	case 379:
		return "K3";
	case 38:
		return "data\\assault.TR2";
	case 380:
		return "Storage Key";
	case 381:
		return "K3";
	case 382:
		return "Rooftops Key";
	case 383:
		return "K3";
	case 384:
		return "K3";
	case 385:
		return "Silver Key";
	case 386:
		return "K3";
	case 387:
		return "K3";
	case 388:
		return "K3";
	case 389:
		return "Iron Key";
	case 39:
		return "data\\wall.TR2";
	case 390:
		return "Cabin Key";
	case 391:
		return "K3";
	case 392:
		return "K4";
	case 393:
		return "K4";
	case 394:
		return "K4";
	case 395:
		return "K4";
	case 396:
		return "K4";
	case 397:
		return "K4";
	case 398:
		return "Blue Pass Card";
	case 399:
		return "K4";
	case 4:
		return "\"Bartoli's Hideout\"";
	case 40:
		return "data\\boat.TR2";
	case 400:
		return "K4";
	case 401:
		return "K4";
	case 402:
		return "Cabin Key";
	case 403:
		return "K4";
	case 404:
		return "Main Hall Key";
	case 405:
		return "K4";
	case 406:
		return "K4";
	case 407:
		return "Main Chamber Key";
	case 408:
		return "K4";
	case 409:
		return "K4";
	case 41:
		return "data\\venice.TR2";
	case 410:
		return "K4";
	case 411:
		return "K4";
	case 412:
		return "K4";
	case 413:
		return "K4";
	case 414:
		return "Touch options";
	case 415:
		return "Adjust Position";
	case 416:
		return "Fixed controls: Off";
	case 417:
		return "Fixed controls: On";
	case 418:
		return "Auto run: Off";
	case 419:
		return "Auto run: On";
	case 42:
		return "data\\opera.TR2";
	case 420:
		return "Auto grab: Off";
	case 421:
		return "Auto grab: On";
	case 422:
		return "UI Scale: Smaller";
	case 423:
		return "UI Scale: Normal";
	case 424:
		return "UI Scale: Larger";
	case 425:
		return "Lara is waiting for you in Tomb Raider. Come back and play!";
	case 426:
		return "Controller connected";
	case 427:
		return "Controller disconnected";
	case 428:
		return "Back button: Exit. Hold to reset.";
	case 429:
		return "A new screen got connected";
	case 43:
		return "data\\rig.TR2";
	case 430:
		return "A screen got disconnected";
	case 431:
		return "It has been a week, and Lara is still waiting for you in Tomb Raider. Come back and play!";
	case 432:
		return "It has been a month, and Lara is still waiting for you in Tomb Raider. Come back and play!";
	case 433:
		return "Play Tomb Raider for Android";
	case 434:
		return "\"Congratulations. You've beat Tomb Raider Classic game!\"";
	case 435:
		return "\"Lara's Home\"";
	case 436:
		return "The Cold War";
	case 437:
		return "\"Fool's Gold\"";
	case 438:
		return "Furnace of the Gods";
	case 439:
		return "Kingdom";
	case 44:
		return "data\\platform.TR2";
	case 440:
		return "Nightmare In Vegas";
	case 441:
		return "data\\title.TR2";
	case 442:
		return "data\\title.pcx";
	case 443:
		return "data\\legal.pcx";
	case 444:
		return "data\\titleUS.pcx";
	case 445:
		return "data\\legalUS.pcx";
	case 446:
		return "data\\titleJAP.pcx";
	case 447:
		return "data\\legalJAP.pcx";
	case 448:
		return "data\\assault.TR2";
	case 449:
		return "data\\level1.TR2";
	case 45:
		return "data\\unwater.TR2";
	case 450:
		return "data\\level2.TR2";
	case 451:
		return "data\\level3.TR2";
	case 452:
		return "data\\level4.TR2";
	case 453:
		return "data\\level5.TR2";
	case 454:
		return "INVENTORY";
	case 455:
		return "OPTIONS";
	case 456:
		return "ITEMS";
	case 457:
		return "GAME OVER";
	case 458:
		return "Load Game";
	case 459:
		return "Save Game";
	case 46:
		return "data\\keel.TR2";
	case 460:
		return "New Game";
	case 461:
		return "Restart Level";
	case 462:
		return "Exit to Title";
	case 463:
		return "Exit Demo";
	case 464:
		return "Exit Game";
	case 465:
		return "Select Level";
	case 466:
		return "Save Position";
	case 467:
		return "Select Detail";
	case 468:
		return "High";
	case 469:
		return "Medium";
	case 47:
		return "data\\living.TR2";
	case 470:
		return "Low";
	case 471:
		return "Walk";
	case 472:
		return "Roll";
	case 473:
		return "Run";
	case 474:
		return "Left";
	case 475:
		return "Right";
	case 476:
		return "Back";
	case 477:
		return "Step Left";
	case 478:
		return "";
	case 479:
		return "Step Right";
	case 48:
		return "data\\deck.TR2";
	case 480:
		return "";
	case 481:
		return "Look";
	case 482:
		return "Jump";
	case 483:
		return "Action";
	case 484:
		return "Draw Weapon";
	case 485:
		return "";
	case 486:
		return "Inventory";
	case 487:
		return "Flare";
	case 488:
		return "Step";
	case 489:
		return "Statistics";
	case 49:
		return "data\\skidoo.TR2";
	case 490:
		return "Pistols";
	case 491:
		return "Shotgun";
	case 492:
		return "Automatic Pistols";
	case 493:
		return "Uzis";
	case 494:
		return "Harpoon Gun";
	case 495:
		return "M16";
	case 496:
		return "Grenade Launcher";
	case 497:
		return "Flare";
	case 498:
		return "Pistol Clips";
	case 499:
		return "Shotgun Shells";
	case 5:
		return "Opera House";
	case 50:
		return "data\\monastry.TR2";
	case 500:
		return "Automatic Pistol Clips";
	case 501:
		return "Uzi Clips";
	case 502:
		return "Harpoons";
	case 503:
		return "M16 Clips";
	case 504:
		return "Grenades";
	case 505:
		return "Small Medi Pack";
	case 506:
		return "Large Medi Pack";
	case 507:
		return "Pickup";
	case 508:
		return "Puzzle";
	case 509:
		return "Key";
	case 51:
		return "data\\catacomb.TR2";
	case 510:
		return "Game";
	case 511:
		return "\"Lara's Home\"";
	case 512:
		return "LOADING";
	case 513:
		return "Time Taken";
	case 514:
		return "Secrets Found";
	case 515:
		return "Location";
	case 516:
		return "Kills";
	case 517:
		return "Ammo Used";
	case 518:
		return "Hits";
	case 519:
		return "Saves Performed";
	case 52:
		return "data\\icecave.TR2";
	case 520:
		return "Distance Travelled";
	case 521:
		return "Health Packs Used";
	case 522:
		return "Release Version 1.1";
	case 523:
		return "None";
	case 524:
		return "Finish";
	case 525:
		return "BEST TIMES";
	case 526:
		return "No Times Set";
	case 527:
		return "N/A";
	case 528:
		return "Current Position";
	case 529:
		return "Final Statistics";
	case 53:
		return "data\\emprtomb.TR2";
	case 530:
		return "of";
	case 531:
		return "Story so far...";
	case 532:
		return "spare";
	case 533:
		return "spare";
	case 534:
		return "spare";
	case 535:
		return "spare";
	case 536:
		return "spare";
	case 537:
		return "spare";
	case 538:
		return "spare";
	case 539:
		return "spare";
	case 54:
		return "data\\floating.TR2";
	case 540:
		return "spare";
	case 541:
		return "spare";
	case 542:
		return "spare";
	case 543:
		return "Detail Levels";
	case 544:
		return "Demo Mode";
	case 545:
		return "Sound";
	case 546:
		return "Controls";
	case 547:
		return "Gamma";
	case 548:
		return "Set Volumes";
	case 549:
		return "User Keys";
	case 55:
		return "data\\xian.TR2";
	case 550:
		return "The file could not be saved!";
	case 551:
		return "Try Again?";
	case 552:
		return "YES";
	case 553:
		return "NO";
	case 554:
		return "Save Complete!";
	case 555:
		return "No save games!";
	case 556:
		return "None valid";
	case 557:
		return "Save Game?";
	case 558:
		return "- EMPTY SLOT -";
	case 559:
		return "OFF";
	case 56:
		return "data\\house.TR2";
	case 560:
		return "ON";
	case 561:
		return "Setup Sound Card";
	case 562:
		return "Default Keys";
	case 563:
		return "DOZY";
	case 564:
		return "spare";
	case 565:
		return "spare";
	case 566:
		return "spare";
	case 567:
		return "spare";
	case 568:
		return "spare";
	case 569:
		return "spare";
	case 57:
		return "data\\boat.tr2";
	case 570:
		return "spare";
	case 571:
		return "spare";
	case 572:
		return "spare";
	case 573:
		return "spare";
	case 574:
		return "spare";
	case 575:
		return "spare";
	case 576:
		return "spare";
	case 577:
		return "spare";
	case 578:
		return "spare";
	case 579:
		return "spare";
	case 58:
		return "data\\keel.tr2";
	case 580:
		return "spare";
	case 581:
		return "spare";
	case 582:
		return "spare";
	case 583:
		return "spare";
	case 584:
		return "P1";
	case 585:
		return "P1";
	case 586:
		return "Circuit Board";
	case 587:
		return "Mask Of Tornarsuk";
	case 588:
		return "Mask Of Tornarsuk";
	case 589:
		return "Elevator Junction";
	case 59:
		return "data\\skidoo.tr2";
	case 590:
		return "P2";
	case 591:
		return "P2";
	case 592:
		return "P2";
	case 593:
		return "Gold Nugget";
	case 594:
		return "P2";
	case 595:
		return "Door Circuit";
	case 596:
		return "P3";
	case 597:
		return "P3";
	case 598:
		return "P3";
	case 599:
		return "P3";
	case 6:
		return "Offshore Rig";
	case 60:
		return "data\\cut1.TR2";
	case 600:
		return "P3";
	case 601:
		return "P3";
	case 602:
		return "P4";
	case 603:
		return "P4";
	case 604:
		return "P4";
	case 605:
		return "P4";
	case 606:
		return "P4";
	case 607:
		return "P4";
	case 608:
		return "P1";
	case 609:
		return "P1";
	case 61:
		return "data\\cut2.TR2";
	case 610:
		return "P1";
	case 611:
		return "P1";
	case 612:
		return "P1";
	case 613:
		return "P1";
	case 614:
		return "P2";
	case 615:
		return "P2";
	case 616:
		return "P2";
	case 617:
		return "P2";
	case 618:
		return "P2";
	case 619:
		return "P2";
	case 62:
		return "data\\cut3.TR2";
	case 620:
		return "K1";
	case 621:
		return "Guardroom Key";
	case 622:
		return "CardKey 1";
	case 623:
		return "K1";
	case 624:
		return "K1";
	case 625:
		return "Hotel Key";
	case 626:
		return "K2";
	case 627:
		return "\"Shaft 'B' Key\"";
	case 628:
		return "K2";
	case 629:
		return "K2";
	case 63:
		return "data\\cut4.TR2";
	case 630:
		return "K2";
	case 631:
		return "K2";
	case 632:
		return "K3";
	case 633:
		return "K3";
	case 634:
		return "K3";
	case 635:
		return "K3";
	case 636:
		return "K3";
	case 637:
		return "K3";
	case 638:
		return "K4";
	case 639:
		return "K4";
	case 64:
		return "INVENTORY";
	case 640:
		return "CardKey 2";
	case 641:
		return "K4";
	case 642:
		return "K4";
	case 643:
		return "K4";
	case 644:
		return "Stone dragon found!";
	case 645:
		return "Jade dragon found!";
	case 646:
		return "Gold dragon found!";
	case 647:
		return "Golden coins found!";
	case 648:
		return "Golden bars found!";
	case 649:
		return "Golden skull found!";
	case 65:
		return "OPTIONS";
	case 650:
		return "Language changed. Please restart or exit to apply changes.";
	case 66:
		return "ITEMS";
	case 67:
		return "GAME OVER";
	case 68:
		return "Load Game";
	case 69:
		return "Save Game";
	case 7:
		return "Diving Area";
	case 70:
		return "New Game";
	case 71:
		return "Restart Level";
	case 72:
		return "Exit to Title";
	case 73:
		return "Exit Demo";
	case 74:
		return "Exit Game";
	case 75:
		return "Select Level";
	case 76:
		return "Save Position";
	case 77:
		return "Select Detail";
	case 78:
		return "High";
	case 79:
		return "Medium";
	case 8:
		return "40 Fathoms";
	case 80:
		return "Low";
	case 81:
		return "Walk";
	case 82:
		return "Roll";
	case 83:
		return "Run";
	case 84:
		return "Left";
	case 85:
		return "Right";
	case 86:
		return "Back";
	case 87:
		return "Step Left";
	case 88:
		return "";
	case 89:
		return "Step Right";
	case 9:
		return "Wreck of the Maria Doria";
	case 90:
		return "";
	case 91:
		return "Look";
	case 92:
		return "Jump";
	case 93:
		return "Action";
	case 94:
		return "Draw Weapon";
	case 95:
		return "";
	case 96:
		return "Inventory";
	case 97:
		return "Flare";
	case 98:
		return "Step";
	case 99:
		return "Statistics";
	default:
		return " ";
	}
}

char *tr2_fmv_path[6] = {NULL, NULL, NULL, NULL, NULL, NULL};

void S_EnqueueFMV(char *name) {
	for (int i = 0; i < 6; i++) {
		if (!tr2_fmv_path[i]) {
			tr2_fmv_path[i] = (char *)malloc(256);
			sprintf(tr2_fmv_path[i], "%s/%s_VITA.mp4", DATA_PATH, name);
			break;
		}
	}
}

uint32_t oldpad_fmv = 0;
int S_CheckPendingFMV() {
	SceCtrlData pad;
	if (tr2_fmv_path[0]) {
		playMovie(tr2_fmv_path[0]);
		while (getMovieState() != PLAYER_INACTIVE) {
			sceCtrlPeekBufferPositiveExt2(0, &pad, 1);
			if (pad.buttons & SCE_CTRL_CROSS && (!(oldpad_fmv & SCE_CTRL_CROSS)))
				stopMovie();
			oldpad_fmv = pad.buttons;
			glDisable(GL_DEPTH_TEST);
			vglSwapBuffers(GL_FALSE);
		}
		glEnable(GL_DEPTH_TEST);
		free(tr2_fmv_path[0]);
		tr2_fmv_path[0] = NULL;
		if (tr2_fmv_path[1]) {
			for (int i = 1; i < 6; i++) {
				if (tr2_fmv_path[i]) {
					tr2_fmv_path[i - 1] = tr2_fmv_path[i];
					tr2_fmv_path[i] = NULL;
				}
			}
			return S_CheckPendingFMV();
		}
	}
	return 0;
}

void patch_game(void) {
	// Tomb Raider 2 related patches
	hook_addr(so_symbol(&tombraider_mod, "S_CheckPendingFMV"), (uintptr_t)&S_CheckPendingFMV);
	hook_addr(so_symbol(&tombraider_mod, "S_EnqueueFMV"), (uintptr_t)&S_EnqueueFMV);
	hook_addr(so_symbol(&tombraider_mod, "S_LocalizedString"), (uintptr_t)&S_LocalizedString);
	hook_addr(so_symbol(&tombraider_mod, "Android_JNI_Vibrate"), (uintptr_t)&ret0);
	hook_addr(so_symbol(&tombraider_mod, "Android_JNI_ShowProgressHUD"), (uintptr_t)&ret0);
	
	hook_addr(so_symbol(&tombraider_mod, "_Z18S_SetTrackingValuePKcS0_"), (uintptr_t)&ret0);
	hook_addr(so_symbol(&tombraider_mod, "S_SetTrackingValue"), (uintptr_t)&ret0);
	hook_addr(so_symbol(&tombraider_mod, "S_FileUpdatedFromCloud"), (uintptr_t)&ret0);
	hook_addr(so_symbol(&tombraider_mod, "Android_JNI_SocialShareURL"), (uintptr_t)&ret0);
	hook_addr(so_symbol(&tombraider_mod, "Android_JNI_ShowToast"), (uintptr_t)&ret0);

	//hook_addr(so_symbol(&tombraider_mod, "SDL_AddBasicVideoDisplay"), (uintptr_t)&SDL_AddBasicVideoDisplay);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_AddDisplayMode"), (uintptr_t)&SDL_AddDisplayMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AddEventWatch"), (uintptr_t)&SDL_AddEventWatch);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AddTimer"), (uintptr_t)&SDL_AddTimer);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_AddTouch"), (uintptr_t)&SDL_AddTouch);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_AddVideoDisplay"), (uintptr_t)&SDL_AddVideoDisplay);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_AllocBlitMap"), (uintptr_t)&SDL_AllocBlitMap);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AllocFormat"), (uintptr_t)&SDL_AllocFormat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AllocPalette"), (uintptr_t)&SDL_AllocPalette);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AllocRW"), (uintptr_t)&SDL_AllocRW);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_AndroidGetActivity"), (uintptr_t)&SDL_AndroidGetActivity);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AndroidGetExternalCachePath"), (uintptr_t)&SDL_AndroidGetExternalStoragePath);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AndroidGetExternalStoragePath"), (uintptr_t)&SDL_AndroidGetExternalStoragePath);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AndroidGetExternalStorageState"), (uintptr_t)&ret0);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AndroidGetInternalStoragePath"), (uintptr_t)&SDL_AndroidGetInternalStoragePath);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AndroidGetJNIEnv"), (uintptr_t)&Android_JNI_GetEnv);
	hook_addr(so_symbol(&tombraider_mod, "Android_JNI_GetEnv"), (uintptr_t)&Android_JNI_GetEnv);
	hook_addr(so_symbol(&tombraider_mod, "SDL_Android_Init"), (uintptr_t)&ret0);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_AssertionsInit"), (uintptr_t)&SDL_AssertionsInit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_AssertionsQuit"), (uintptr_t)&SDL_AssertionsQuit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AtomicCAS"), (uintptr_t)&SDL_AtomicCAS);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AtomicCASPtr"), (uintptr_t)&SDL_AtomicCASPtr);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AtomicLock"), (uintptr_t)&SDL_AtomicLock);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AtomicTryLock"), (uintptr_t)&SDL_AtomicTryLock);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AtomicUnlock"), (uintptr_t)&SDL_AtomicUnlock);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AudioInit"), (uintptr_t)&SDL_AudioInit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_AudioQuit"), (uintptr_t)&SDL_AudioQuit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_BlendFillRect"), (uintptr_t)&SDL_BlendFillRect);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_BlendFillRects"), (uintptr_t)&SDL_BlendFillRects);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_BlendLine"), (uintptr_t)&SDL_BlendLine);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_BlendLines"), (uintptr_t)&SDL_BlendLines);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_BlendPoint"), (uintptr_t)&SDL_BlendPoint);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_BlendPoints"), (uintptr_t)&SDL_BlendPoints);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_BlitCopy"), (uintptr_t)&SDL_BlitCopy);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_Blit_Slow"), (uintptr_t)&SDL_Blit_Slow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_BuildAudioCVT"), (uintptr_t)&SDL_BuildAudioCVT);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateAudioSpec"), (uintptr_t)&SDL_CalculateAudioSpec);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateBlit"), (uintptr_t)&SDL_CalculateBlit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateBlit0"), (uintptr_t)&SDL_CalculateBlit0);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateBlit1"), (uintptr_t)&SDL_CalculateBlit1);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateBlitA"), (uintptr_t)&SDL_CalculateBlitA);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateBlitN"), (uintptr_t)&SDL_CalculateBlitN);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateGammaRamp"), (uintptr_t)&SDL_CalculateGammaRamp);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculatePitch"), (uintptr_t)&SDL_CalculatePitch);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateShapeBitmap"), (uintptr_t)&SDL_CalculateShapeBitmap);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_CalculateShapeTree"), (uintptr_t)&SDL_CalculateShapeTree);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ClearError"), (uintptr_t)&SDL_ClearError);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ClearHints"), (uintptr_t)&SDL_ClearHints);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CloseAudio"), (uintptr_t)&SDL_CloseAudio);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CloseAudioDevice"), (uintptr_t)&SDL_CloseAudioDevice);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CondBroadcast"), (uintptr_t)&SDL_CondBroadcast);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CondSignal"), (uintptr_t)&SDL_CondSignal);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CondWait"), (uintptr_t)&SDL_CondWait);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CondWaitTimeout"), (uintptr_t)&SDL_CondWaitTimeout);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ConvertAudio"), (uintptr_t)&SDL_ConvertAudio);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ConvertPixels"), (uintptr_t)&SDL_ConvertPixels);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ConvertSurface"), (uintptr_t)&SDL_ConvertSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ConvertSurfaceFormat"), (uintptr_t)&SDL_ConvertSurfaceFormat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateColorCursor"), (uintptr_t)&SDL_CreateColorCursor);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateCond"), (uintptr_t)&SDL_CreateCond);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateCursor"), (uintptr_t)&SDL_CreateCursor);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateMutex"), (uintptr_t)&SDL_CreateMutex);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateRGBSurface"), (uintptr_t)&SDL_CreateRGBSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateRGBSurfaceFrom"), (uintptr_t)&SDL_CreateRGBSurfaceFrom);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateRenderer"), (uintptr_t)&SDL_CreateRenderer);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateSemaphore"), (uintptr_t)&SDL_CreateSemaphore);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateShapedWindow"), (uintptr_t)&SDL_CreateShapedWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateSoftwareRenderer"), (uintptr_t)&SDL_CreateSoftwareRenderer);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateSystemCursor"), (uintptr_t)&SDL_CreateSystemCursor);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateTexture"), (uintptr_t)&SDL_CreateTexture);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateTextureFromSurface"), (uintptr_t)&SDL_CreateTextureFromSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateThread"), (uintptr_t)&SDL_CreateThread);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateWindow"), (uintptr_t)&SDL_CreateWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateWindowAndRenderer"), (uintptr_t)&SDL_CreateWindowAndRenderer);
	hook_addr(so_symbol(&tombraider_mod, "SDL_CreateWindowFrom"), (uintptr_t)&SDL_CreateWindowFrom);
	hook_addr(so_symbol(&tombraider_mod, "SDL_DelEventWatch"), (uintptr_t)&SDL_DelEventWatch);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_DelFinger"), (uintptr_t)&SDL_DelFinger);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_DelTouch"), (uintptr_t)&SDL_DelTouch);
	hook_addr(so_symbol(&tombraider_mod, "SDL_Delay"), (uintptr_t)&SDL_Delay);
	hook_addr(so_symbol(&tombraider_mod, "SDL_DestroyCond"), (uintptr_t)&SDL_DestroyCond);
	hook_addr(so_symbol(&tombraider_mod, "SDL_DestroyMutex"), (uintptr_t)&SDL_DestroyMutex);
	hook_addr(so_symbol(&tombraider_mod, "SDL_DestroyRenderer"), (uintptr_t)&SDL_DestroyRenderer);
	hook_addr(so_symbol(&tombraider_mod, "SDL_DestroySemaphore"), (uintptr_t)&SDL_DestroySemaphore);
	hook_addr(so_symbol(&tombraider_mod, "SDL_DestroyTexture"), (uintptr_t)&SDL_DestroyTexture);
	hook_addr(so_symbol(&tombraider_mod, "SDL_DestroyWindow"), (uintptr_t)&SDL_DestroyWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_DisableScreenSaver"), (uintptr_t)&SDL_DisableScreenSaver);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_DitherColors"), (uintptr_t)&SDL_DitherColors);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_DrawLine"), (uintptr_t)&SDL_DrawLine);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_DrawLines"), (uintptr_t)&SDL_DrawLines);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_DrawPoint"), (uintptr_t)&SDL_DrawPoint);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_DrawPoints"), (uintptr_t)&SDL_DrawPoints);
	hook_addr(so_symbol(&tombraider_mod, "SDL_EnableScreenSaver"), (uintptr_t)&SDL_EnableScreenSaver);
	hook_addr(so_symbol(&tombraider_mod, "SDL_EnclosePoints"), (uintptr_t)&SDL_EnclosePoints);
	hook_addr(so_symbol(&tombraider_mod, "SDL_Error"), (uintptr_t)&SDL_Error);
	hook_addr(so_symbol(&tombraider_mod, "SDL_EventState"), (uintptr_t)&SDL_EventState);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FillRect"), (uintptr_t)&SDL_FillRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FillRects"), (uintptr_t)&SDL_FillRects);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FilterEvents"), (uintptr_t)&SDL_FilterEvents);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_FindColor"), (uintptr_t)&SDL_FindColor);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_FirstAudioFormat"), (uintptr_t)&SDL_FirstAudioFormat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FlushEvent"), (uintptr_t)&SDL_FlushEvent);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FlushEvents"), (uintptr_t)&SDL_FlushEvents);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_FreeBlitMap"), (uintptr_t)&SDL_FreeBlitMap);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FreeCursor"), (uintptr_t)&SDL_FreeCursor);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FreeFormat"), (uintptr_t)&SDL_FreeFormat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FreePalette"), (uintptr_t)&SDL_FreePalette);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FreeRW"), (uintptr_t)&SDL_FreeRW);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_FreeShapeTree"), (uintptr_t)&SDL_FreeShapeTree);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FreeSurface"), (uintptr_t)&SDL_FreeSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_FreeWAV"), (uintptr_t)&SDL_FreeWAV);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_BindTexture"), (uintptr_t)&SDL_GL_BindTexture);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_CreateContext"), (uintptr_t)&SDL_GL_CreateContext);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_DeleteContext"), (uintptr_t)&SDL_GL_DeleteContext);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_ExtensionSupported"), (uintptr_t)&SDL_GL_ExtensionSupported);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_GetAttribute"), (uintptr_t)&SDL_GL_GetAttribute);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_GetProcAddress"), (uintptr_t)&SDL_GL_GetProcAddress);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_GetSwapInterval"), (uintptr_t)&SDL_GL_GetSwapInterval);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_LoadLibrary"), (uintptr_t)&SDL_GL_LoadLibrary);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_MakeCurrent"), (uintptr_t)&SDL_GL_MakeCurrent);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_SetAttribute"), (uintptr_t)&SDL_GL_SetAttribute);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_SetSwapInterval"), (uintptr_t)&SDL_GL_SetSwapInterval);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_SwapWindow"), (uintptr_t)&SDL_GL_SwapWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_UnbindTexture"), (uintptr_t)&SDL_GL_UnbindTexture);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GL_UnloadLibrary"), (uintptr_t)&SDL_GL_UnloadLibrary);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerAddMapping"), (uintptr_t)&SDL_GameControllerAddMapping);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerClose"), (uintptr_t)&SDL_GameControllerClose);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerEventState"), (uintptr_t)&SDL_GameControllerEventState);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerEventWatcher"), (uintptr_t)&SDL_GameControllerEventWatcher);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetAttached"), (uintptr_t)&SDL_GameControllerGetAttached);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetAxis"), (uintptr_t)&SDL_GameControllerGetAxis);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetAxisFromString"), (uintptr_t)&SDL_GameControllerGetAxisFromString);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetBindForAxis"), (uintptr_t)&SDL_GameControllerGetBindForAxis);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetBindForButton"), (uintptr_t)&SDL_GameControllerGetBindForButton);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetButton"), (uintptr_t)&SDL_GameControllerGetButton);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetButtonFromString"), (uintptr_t)&SDL_GameControllerGetButtonFromString);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetJoystick"), (uintptr_t)&SDL_GameControllerGetJoystick);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetStringForAxis"), (uintptr_t)&SDL_GameControllerGetStringForAxis);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerGetStringForButton"), (uintptr_t)&SDL_GameControllerGetStringForButton);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerInit"), (uintptr_t)&SDL_GameControllerInit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerMapping"), (uintptr_t)&SDL_GameControllerMapping);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerMappingForGUID"), (uintptr_t)&SDL_GameControllerMappingForGUID);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerName"), (uintptr_t)&SDL_GameControllerName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerNameForIndex"), (uintptr_t)&SDL_GameControllerNameForIndex);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerOpen"), (uintptr_t)&SDL_GameControllerOpen);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerQuit"), (uintptr_t)&SDL_GameControllerQuit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GameControllerUpdate"), (uintptr_t)&SDL_GameControllerUpdate);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GestureAddTouch"), (uintptr_t)&SDL_GestureAddTouch);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GestureProcessEvent"), (uintptr_t)&SDL_GestureProcessEvent);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetAssertionReport"), (uintptr_t)&SDL_GetAssertionReport);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetAudioDeviceName"), (uintptr_t)&SDL_GetAudioDeviceName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetAudioDeviceStatus"), (uintptr_t)&SDL_GetAudioDeviceStatus);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetAudioDriver"), (uintptr_t)&SDL_GetAudioDriver);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetAudioStatus"), (uintptr_t)&SDL_GetAudioStatus);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetCPUCacheLineSize"), (uintptr_t)&SDL_GetCPUCacheLineSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetCPUCount"), (uintptr_t)&SDL_GetCPUCount);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetClipRect"), (uintptr_t)&SDL_GetClipRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetClipboardText"), (uintptr_t)&SDL_GetClipboardText);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetClosestDisplayMode"), (uintptr_t)&SDL_GetClosestDisplayMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetColorKey"), (uintptr_t)&SDL_GetColorKey);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetCurrentAudioDriver"), (uintptr_t)&SDL_GetCurrentAudioDriver);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetCurrentDisplayMode"), (uintptr_t)&SDL_GetCurrentDisplayMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetCurrentVideoDriver"), (uintptr_t)&SDL_GetCurrentVideoDriver);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetCursor"), (uintptr_t)&SDL_GetCursor);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetDefaultKeymap"), (uintptr_t)&SDL_GetDefaultKeymap);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetDesktopDisplayMode"), (uintptr_t)&SDL_GetDesktopDisplayMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetDisplayBounds"), (uintptr_t)&SDL_GetDisplayBounds);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetDisplayForWindow"), (uintptr_t)&SDL_GetDisplayForWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetDisplayMode"), (uintptr_t)&SDL_GetDisplayMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetDisplayName"), (uintptr_t)&SDL_GetDisplayName);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetErrBuf"), (uintptr_t)&SDL_GetErrBuf);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetError"), (uintptr_t)&SDL_GetError);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetEventFilter"), (uintptr_t)&SDL_GetEventFilter);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetFinger"), (uintptr_t)&SDL_GetFinger);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetFocusWindow"), (uintptr_t)&SDL_GetFocusWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetHint"), (uintptr_t)&SDL_GetHint);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetKeyFromName"), (uintptr_t)&SDL_GetKeyFromName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetKeyFromScancode"), (uintptr_t)&SDL_GetKeyFromScancode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetKeyName"), (uintptr_t)&SDL_GetKeyName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetKeyboardFocus"), (uintptr_t)&SDL_GetKeyboardFocus);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetKeyboardState"), (uintptr_t)&SDL_GetKeyboardState);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetModState"), (uintptr_t)&SDL_GetModState);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetMouse"), (uintptr_t)&SDL_GetMouse);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetMouseFocus"), (uintptr_t)&SDL_GetMouseFocus);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetMouseState"), (uintptr_t)&SDL_GetMouseState);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetNumAudioDevices"), (uintptr_t)&SDL_GetNumAudioDevices);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetNumAudioDrivers"), (uintptr_t)&SDL_GetNumAudioDrivers);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetNumDisplayModes"), (uintptr_t)&SDL_GetNumDisplayModes);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetNumRenderDrivers"), (uintptr_t)&SDL_GetNumRenderDrivers);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetNumTouchDevices"), (uintptr_t)&SDL_GetNumTouchDevices);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetNumTouchFingers"), (uintptr_t)&SDL_GetNumTouchFingers);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetNumVideoDisplays"), (uintptr_t)&SDL_GetNumVideoDisplays);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetNumVideoDrivers"), (uintptr_t)&SDL_GetNumVideoDrivers);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetPerformanceCounter"), (uintptr_t)&SDL_GetPerformanceCounter);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetPerformanceFrequency"), (uintptr_t)&SDL_GetPerformanceFrequency);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetPixelFormatName"), (uintptr_t)&SDL_GetPixelFormatName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetPlatform"), (uintptr_t)&SDL_GetPlatform);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetPowerInfo"), (uintptr_t)&SDL_GetPowerInfo);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetPowerInfo_Android"), (uintptr_t)&SDL_GetPowerInfo_Android);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRGB"), (uintptr_t)&SDL_GetRGB);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRGBA"), (uintptr_t)&SDL_GetRGBA);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRelativeMouseMode"), (uintptr_t)&SDL_GetRelativeMouseMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRelativeMouseState"), (uintptr_t)&SDL_GetRelativeMouseState);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRenderDrawBlendMode"), (uintptr_t)&SDL_GetRenderDrawBlendMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRenderDrawColor"), (uintptr_t)&SDL_GetRenderDrawColor);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRenderDriverInfo"), (uintptr_t)&SDL_GetRenderDriverInfo);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRenderTarget"), (uintptr_t)&SDL_GetRenderTarget);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRenderer"), (uintptr_t)&SDL_GetRenderer);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRendererInfo"), (uintptr_t)&SDL_GetRendererInfo);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRevision"), (uintptr_t)&SDL_GetRevision);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetRevisionNumber"), (uintptr_t)&SDL_GetRevisionNumber);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetScancodeFromKey"), (uintptr_t)&SDL_GetScancodeFromKey);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetScancodeFromName"), (uintptr_t)&SDL_GetScancodeFromName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetScancodeName"), (uintptr_t)&SDL_GetScancodeName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetShapedWindowMode"), (uintptr_t)&SDL_GetShapedWindowMode);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetSpanEnclosingRect"), (uintptr_t)&SDL_GetSpanEnclosingRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetSurfaceAlphaMod"), (uintptr_t)&SDL_GetSurfaceAlphaMod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetSurfaceBlendMode"), (uintptr_t)&SDL_GetSurfaceBlendMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetSurfaceColorMod"), (uintptr_t)&SDL_GetSurfaceColorMod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetTextureAlphaMod"), (uintptr_t)&SDL_GetTextureAlphaMod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetTextureBlendMode"), (uintptr_t)&SDL_GetTextureBlendMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetTextureColorMod"), (uintptr_t)&SDL_GetTextureColorMod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetThreadID"), (uintptr_t)&SDL_GetThreadID);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetThreadName"), (uintptr_t)&SDL_GetThreadName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetTicks"), (uintptr_t)&SDL_GetTicks);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetTouch"), (uintptr_t)&SDL_GetTouch);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetTouchDevice"), (uintptr_t)&SDL_GetTouchDevice);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetTouchFinger"), (uintptr_t)&SDL_GetTouchFinger);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetVersion"), (uintptr_t)&SDL_GetVersion);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetVideoDevice"), (uintptr_t)&SDL_GetVideoDevice);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetVideoDriver"), (uintptr_t)&SDL_GetVideoDriver);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowBrightness"), (uintptr_t)&SDL_GetWindowBrightness);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowData"), (uintptr_t)&SDL_GetWindowData);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowDisplayIndex"), (uintptr_t)&SDL_GetWindowDisplayIndex);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowDisplayMode"), (uintptr_t)&SDL_GetWindowDisplayMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowFlags"), (uintptr_t)&SDL_GetWindowFlags);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowFromID"), (uintptr_t)&SDL_GetWindowFromID);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowGammaRamp"), (uintptr_t)&SDL_GetWindowGammaRamp);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowGrab"), (uintptr_t)&SDL_GetWindowGrab);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowID"), (uintptr_t)&SDL_GetWindowID);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowMaximumSize"), (uintptr_t)&SDL_GetWindowMaximumSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowMinimumSize"), (uintptr_t)&SDL_GetWindowMinimumSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowPixelFormat"), (uintptr_t)&SDL_GetWindowPixelFormat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowPosition"), (uintptr_t)&SDL_GetWindowPosition);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowSize"), (uintptr_t)&SDL_GetWindowSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowSurface"), (uintptr_t)&SDL_GetWindowSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowTitle"), (uintptr_t)&SDL_GetWindowTitle);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_GetWindowWMInfo"), (uintptr_t)&SDL_GetWindowWMInfo);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticClose"), (uintptr_t)&SDL_HapticClose);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticDestroyEffect"), (uintptr_t)&SDL_HapticDestroyEffect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticEffectSupported"), (uintptr_t)&SDL_HapticEffectSupported);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticGetEffectStatus"), (uintptr_t)&SDL_HapticGetEffectStatus);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticIndex"), (uintptr_t)&SDL_HapticIndex);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_HapticInit"), (uintptr_t)&SDL_HapticInit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticName"), (uintptr_t)&SDL_HapticName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticNewEffect"), (uintptr_t)&SDL_HapticNewEffect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticNumAxes"), (uintptr_t)&SDL_HapticNumAxes);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticNumEffects"), (uintptr_t)&SDL_HapticNumEffects);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticNumEffectsPlaying"), (uintptr_t)&SDL_HapticNumEffectsPlaying);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticOpen"), (uintptr_t)&SDL_HapticOpen);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticOpenFromJoystick"), (uintptr_t)&SDL_HapticOpenFromJoystick);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticOpenFromMouse"), (uintptr_t)&SDL_HapticOpenFromMouse);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticOpened"), (uintptr_t)&SDL_HapticOpened);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticPause"), (uintptr_t)&SDL_HapticPause);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticQuery"), (uintptr_t)&SDL_HapticQuery);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_HapticQuit"), (uintptr_t)&SDL_HapticQuit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticRumbleInit"), (uintptr_t)&SDL_HapticRumbleInit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticRumblePlay"), (uintptr_t)&SDL_HapticRumblePlay);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticRumbleStop"), (uintptr_t)&SDL_HapticRumbleStop);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticRumbleSupported"), (uintptr_t)&SDL_HapticRumbleSupported);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticRunEffect"), (uintptr_t)&SDL_HapticRunEffect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticSetAutocenter"), (uintptr_t)&SDL_HapticSetAutocenter);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticSetGain"), (uintptr_t)&SDL_HapticSetGain);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticStopAll"), (uintptr_t)&SDL_HapticStopAll);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticStopEffect"), (uintptr_t)&SDL_HapticStopEffect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticUnpause"), (uintptr_t)&SDL_HapticUnpause);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HapticUpdateEffect"), (uintptr_t)&SDL_HapticUpdateEffect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_Has3DNow"), (uintptr_t)&SDL_Has3DNow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasAltiVec"), (uintptr_t)&SDL_HasAltiVec);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasClipboardText"), (uintptr_t)&SDL_HasClipboardText);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasEvent"), (uintptr_t)&SDL_HasEvent);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasEvents"), (uintptr_t)&SDL_HasEvents);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasIntersection"), (uintptr_t)&SDL_HasIntersection);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasMMX"), (uintptr_t)&SDL_HasMMX);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasRDTSC"), (uintptr_t)&SDL_HasRDTSC);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasSSE"), (uintptr_t)&SDL_HasSSE);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasSSE2"), (uintptr_t)&SDL_HasSSE2);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasSSE3"), (uintptr_t)&SDL_HasSSE3);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasSSE41"), (uintptr_t)&SDL_HasSSE41);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasSSE42"), (uintptr_t)&SDL_HasSSE42);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HasScreenKeyboardSupport"), (uintptr_t)&SDL_HasScreenKeyboardSupport);
	hook_addr(so_symbol(&tombraider_mod, "SDL_HideWindow"), (uintptr_t)&SDL_HideWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_Init"), (uintptr_t)&SDL_Init);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_InitFormat"), (uintptr_t)&SDL_InitFormat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_InitSubSystem"), (uintptr_t)&SDL_InitSubSystem);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_InstallParachute"), (uintptr_t)&SDL_InstallParachute);
	hook_addr(so_symbol(&tombraider_mod, "SDL_IntersectRect"), (uintptr_t)&SDL_IntersectRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_IntersectRectAndLine"), (uintptr_t)&SDL_IntersectRectAndLine);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_InvalidateMap"), (uintptr_t)&SDL_InvalidateMap);
	hook_addr(so_symbol(&tombraider_mod, "SDL_IsGameController"), (uintptr_t)&SDL_IsGameController);
	hook_addr(so_symbol(&tombraider_mod, "SDL_IsScreenKeyboardShown"), (uintptr_t)&SDL_IsScreenKeyboardShown);
	hook_addr(so_symbol(&tombraider_mod, "SDL_IsScreenSaverEnabled"), (uintptr_t)&SDL_IsScreenSaverEnabled);
	hook_addr(so_symbol(&tombraider_mod, "SDL_IsShapedWindow"), (uintptr_t)&SDL_IsShapedWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_IsTextInputActive"), (uintptr_t)&SDL_IsTextInputActive);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickClose"), (uintptr_t)&SDL_JoystickClose);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickEventState"), (uintptr_t)&SDL_JoystickEventState);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetAttached"), (uintptr_t)&SDL_JoystickGetAttached);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetAxis"), (uintptr_t)&SDL_JoystickGetAxis);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetBall"), (uintptr_t)&SDL_JoystickGetBall);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetButton"), (uintptr_t)&SDL_JoystickGetButton);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetDeviceGUID"), (uintptr_t)&SDL_JoystickGetDeviceGUID);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetGUID"), (uintptr_t)&SDL_JoystickGetGUID);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetGUIDFromString"), (uintptr_t)&SDL_JoystickGetGUIDFromString);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetGUIDString"), (uintptr_t)&SDL_JoystickGetGUIDString);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickGetHat"), (uintptr_t)&SDL_JoystickGetHat);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickInit"), (uintptr_t)&SDL_JoystickInit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickInstanceID"), (uintptr_t)&SDL_JoystickInstanceID);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickIsHaptic"), (uintptr_t)&SDL_JoystickIsHaptic);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickName"), (uintptr_t)&SDL_JoystickName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickNameForIndex"), (uintptr_t)&SDL_JoystickNameForIndex);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickNumAxes"), (uintptr_t)&SDL_JoystickNumAxes);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickNumBalls"), (uintptr_t)&SDL_JoystickNumBalls);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickNumButtons"), (uintptr_t)&SDL_JoystickNumButtons);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickNumHats"), (uintptr_t)&SDL_JoystickNumHats);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickOpen"), (uintptr_t)&SDL_JoystickOpen);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickQuit"), (uintptr_t)&SDL_JoystickQuit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_JoystickUpdate"), (uintptr_t)&SDL_JoystickUpdate);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_KeyboardInit"), (uintptr_t)&SDL_KeyboardInit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_KeyboardQuit"), (uintptr_t)&SDL_KeyboardQuit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LoadBMP_RW"), (uintptr_t)&SDL_LoadBMP_RW);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LoadDollarTemplates"), (uintptr_t)&SDL_LoadDollarTemplates);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LoadFunction"), (uintptr_t)&SDL_LoadFunction);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LoadObject"), (uintptr_t)&SDL_LoadObject);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LoadWAV_RW"), (uintptr_t)&SDL_LoadWAV_RW);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LockAudio"), (uintptr_t)&SDL_LockAudio);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LockAudioDevice"), (uintptr_t)&SDL_LockAudioDevice);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LockMutex"), (uintptr_t)&SDL_LockMutex);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LockSurface"), (uintptr_t)&SDL_LockSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LockTexture"), (uintptr_t)&SDL_LockTexture);
	hook_addr(so_symbol(&tombraider_mod, "SDL_Log"), (uintptr_t)&SDL_Log);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogCritical"), (uintptr_t)&SDL_LogCritical);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogDebug"), (uintptr_t)&SDL_LogDebug);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogError"), (uintptr_t)&SDL_LogError);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogGetOutputFunction"), (uintptr_t)&SDL_LogGetOutputFunction);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogGetPriority"), (uintptr_t)&SDL_LogGetPriority);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogInfo"), (uintptr_t)&SDL_LogInfo);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogMessage"), (uintptr_t)&SDL_LogMessage);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogMessageV"), (uintptr_t)&SDL_LogMessageV);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogResetPriorities"), (uintptr_t)&SDL_LogResetPriorities);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogSetAllPriority"), (uintptr_t)&SDL_LogSetAllPriority);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogSetOutputFunction"), (uintptr_t)&SDL_LogSetOutputFunction);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogSetPriority"), (uintptr_t)&SDL_LogSetPriority);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogVerbose"), (uintptr_t)&SDL_LogVerbose);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LogWarn"), (uintptr_t)&SDL_LogWarn);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LowerBlit"), (uintptr_t)&SDL_LowerBlit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_LowerBlitScaled"), (uintptr_t)&SDL_LowerBlitScaled);
	hook_addr(so_symbol(&tombraider_mod, "SDL_MapRGB"), (uintptr_t)&SDL_MapRGB);
	hook_addr(so_symbol(&tombraider_mod, "SDL_MapRGBA"), (uintptr_t)&SDL_MapRGBA);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_MapSurface"), (uintptr_t)&SDL_MapSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_MasksToPixelFormatEnum"), (uintptr_t)&SDL_MasksToPixelFormatEnum);
	hook_addr(so_symbol(&tombraider_mod, "SDL_MaximizeWindow"), (uintptr_t)&SDL_MaximizeWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_MinimizeWindow"), (uintptr_t)&SDL_MinimizeWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_MixAudio"), (uintptr_t)&SDL_MixAudio);
	hook_addr(so_symbol(&tombraider_mod, "SDL_MixAudioFormat"), (uintptr_t)&SDL_MixAudioFormat);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_MouseInit"), (uintptr_t)&SDL_MouseInit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_MouseIsHaptic"), (uintptr_t)&SDL_MouseIsHaptic);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_MouseQuit"), (uintptr_t)&SDL_MouseQuit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_NextAudioFormat"), (uintptr_t)&SDL_NextAudioFormat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_NumHaptics"), (uintptr_t)&SDL_NumHaptics);
	hook_addr(so_symbol(&tombraider_mod, "SDL_NumJoysticks"), (uintptr_t)&SDL_NumJoysticks);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_OnWindowFocusGained"), (uintptr_t)&SDL_OnWindowFocusGained);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_OnWindowFocusLost"), (uintptr_t)&SDL_OnWindowFocusLost);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_OnWindowHidden"), (uintptr_t)&SDL_OnWindowHidden);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_OnWindowMinimized"), (uintptr_t)&SDL_OnWindowMinimized);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_OnWindowResized"), (uintptr_t)&SDL_OnWindowResized);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_OnWindowRestored"), (uintptr_t)&SDL_OnWindowRestored);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_OnWindowShown"), (uintptr_t)&SDL_OnWindowShown);
	hook_addr(so_symbol(&tombraider_mod, "SDL_OpenAudio"), (uintptr_t)&SDL_OpenAudio);
	hook_addr(so_symbol(&tombraider_mod, "SDL_OpenAudioDevice"), (uintptr_t)&SDL_OpenAudioDevice);
	hook_addr(so_symbol(&tombraider_mod, "SDL_PauseAudio"), (uintptr_t)&SDL_PauseAudio);
	hook_addr(so_symbol(&tombraider_mod, "SDL_PauseAudioDevice"), (uintptr_t)&SDL_PauseAudioDevice);
	hook_addr(so_symbol(&tombraider_mod, "SDL_PeepEvents"), (uintptr_t)&SDL_PeepEvents);
	hook_addr(so_symbol(&tombraider_mod, "SDL_PixelFormatEnumToMasks"), (uintptr_t)&SDL_PixelFormatEnumToMasks);
	hook_addr(so_symbol(&tombraider_mod, "SDL_PollEvent"), (uintptr_t)&SDL_PollEvent);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGameControllerAxis"), (uintptr_t)&SDL_PrivateGameControllerAxis);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGameControllerButton"), (uintptr_t)&SDL_PrivateGameControllerButton);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGameControllerParseButton"), (uintptr_t)&SDL_PrivateGameControllerParseButton);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGameControllerRefreshMapping"), (uintptr_t)&SDL_PrivateGameControllerRefreshMapping);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGetControllerGUIDFromMappingString"), (uintptr_t)&SDL_PrivateGetControllerGUIDFromMappingString);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGetControllerMapping"), (uintptr_t)&SDL_PrivateGetControllerMapping);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGetControllerMappingForGUID"), (uintptr_t)&SDL_PrivateGetControllerMappingForGUID);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGetControllerMappingFromMappingString"), (uintptr_t)&SDL_PrivateGetControllerMappingFromMappingString);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateGetControllerNameFromMappingString"), (uintptr_t)&SDL_PrivateGetControllerNameFromMappingString);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateJoystickAxis"), (uintptr_t)&SDL_PrivateJoystickAxis);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateJoystickBall"), (uintptr_t)&SDL_PrivateJoystickBall);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateJoystickButton"), (uintptr_t)&SDL_PrivateJoystickButton);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateJoystickHat"), (uintptr_t)&SDL_PrivateJoystickHat);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateJoystickNeedsPolling"), (uintptr_t)&SDL_PrivateJoystickNeedsPolling);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateJoystickValid"), (uintptr_t)&SDL_PrivateJoystickValid);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_PrivateLoadButtonMapping"), (uintptr_t)&SDL_PrivateLoadButtonMapping);
	hook_addr(so_symbol(&tombraider_mod, "SDL_PumpEvents"), (uintptr_t)&SDL_PumpEvents);
	hook_addr(so_symbol(&tombraider_mod, "SDL_PushEvent"), (uintptr_t)&SDL_PushEvent);
	hook_addr(so_symbol(&tombraider_mod, "SDL_QueryTexture"), (uintptr_t)&SDL_QueryTexture);
	hook_addr(so_symbol(&tombraider_mod, "SDL_Quit"), (uintptr_t)&SDL_Quit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_QuitInit"), (uintptr_t)&SDL_QuitInit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_QuitQuit"), (uintptr_t)&SDL_QuitQuit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_QuitSubSystem"), (uintptr_t)&SDL_QuitSubSystem);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_RLEAlphaBlit"), (uintptr_t)&SDL_RLEAlphaBlit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_RLEBlit"), (uintptr_t)&SDL_RLEBlit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_RLESurface"), (uintptr_t)&SDL_RLESurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RWFromConstMem"), (uintptr_t)&SDL_RWFromConstMem);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RWFromFP"), (uintptr_t)&SDL_RWFromFP);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RWFromFile"), (uintptr_t)&SDL_RWFromFile_hook);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RWFromMem"), (uintptr_t)&SDL_RWFromMem);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RaiseWindow"), (uintptr_t)&SDL_RaiseWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ReadBE16"), (uintptr_t)&SDL_ReadBE16);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ReadBE32"), (uintptr_t)&SDL_ReadBE32);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ReadBE64"), (uintptr_t)&SDL_ReadBE64);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ReadLE16"), (uintptr_t)&SDL_ReadLE16);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ReadLE32"), (uintptr_t)&SDL_ReadLE32);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ReadLE64"), (uintptr_t)&SDL_ReadLE64);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ReadU8"), (uintptr_t)&SDL_ReadU8);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RecordGesture"), (uintptr_t)&SDL_RecordGesture);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_RecreateWindow"), (uintptr_t)&SDL_RecreateWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RegisterEvents"), (uintptr_t)&SDL_RegisterEvents);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_RegisterHintChangedCb"), (uintptr_t)&SDL_RegisterHintChangedCb);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RemoveTimer"), (uintptr_t)&SDL_RemoveTimer);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderClear"), (uintptr_t)&SDL_RenderClear);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderCopy"), (uintptr_t)&SDL_RenderCopy);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderCopyEx"), (uintptr_t)&SDL_RenderCopyEx);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderDrawLine"), (uintptr_t)&SDL_RenderDrawLine);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderDrawLines"), (uintptr_t)&SDL_RenderDrawLines);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderDrawPoint"), (uintptr_t)&SDL_RenderDrawPoint);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderDrawPoints"), (uintptr_t)&SDL_RenderDrawPoints);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderDrawRect"), (uintptr_t)&SDL_RenderDrawRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderDrawRects"), (uintptr_t)&SDL_RenderDrawRects);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderFillRect"), (uintptr_t)&SDL_RenderFillRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderFillRects"), (uintptr_t)&SDL_RenderFillRects);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderGetLogicalSize"), (uintptr_t)&SDL_RenderGetLogicalSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderGetScale"), (uintptr_t)&SDL_RenderGetScale);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderGetViewport"), (uintptr_t)&SDL_RenderGetViewport);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderPresent"), (uintptr_t)&SDL_RenderPresent);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderReadPixels"), (uintptr_t)&SDL_RenderReadPixels);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderSetLogicalSize"), (uintptr_t)&SDL_RenderSetLogicalSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderSetScale"), (uintptr_t)&SDL_RenderSetScale);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderSetViewport"), (uintptr_t)&SDL_RenderSetViewport);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RenderTargetSupported"), (uintptr_t)&SDL_RenderTargetSupported);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ResetAssertionReport"), (uintptr_t)&SDL_ResetAssertionReport);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_ResetKeyboard"), (uintptr_t)&SDL_ResetKeyboard);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_ResetMouse"), (uintptr_t)&SDL_ResetMouse);
	hook_addr(so_symbol(&tombraider_mod, "SDL_RestoreWindow"), (uintptr_t)&SDL_RestoreWindow);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_RunAudio"), (uintptr_t)&SDL_RunAudio);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_RunThread"), (uintptr_t)&SDL_RunThread);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SW_CopyYUVToRGB"), (uintptr_t)&SDL_SW_CopyYUVToRGB);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SW_CreateYUVTexture"), (uintptr_t)&SDL_SW_CreateYUVTexture);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SW_DestroyYUVTexture"), (uintptr_t)&SDL_SW_DestroyYUVTexture);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SW_LockYUVTexture"), (uintptr_t)&SDL_SW_LockYUVTexture);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SW_QueryYUVTexturePixels"), (uintptr_t)&SDL_SW_QueryYUVTexturePixels);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SW_UnlockYUVTexture"), (uintptr_t)&SDL_SW_UnlockYUVTexture);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SW_UpdateYUVTexture"), (uintptr_t)&SDL_SW_UpdateYUVTexture);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_CreateThread"), (uintptr_t)&SDL_SYS_CreateThread);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_GetInstanceIdOfDeviceIndex"), (uintptr_t)&SDL_SYS_GetInstanceIdOfDeviceIndex);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticClose"), (uintptr_t)&SDL_SYS_HapticClose);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticDestroyEffect"), (uintptr_t)&SDL_SYS_HapticDestroyEffect);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticGetEffectStatus"), (uintptr_t)&SDL_SYS_HapticGetEffectStatus);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticInit"), (uintptr_t)&SDL_SYS_HapticInit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticMouse"), (uintptr_t)&SDL_SYS_HapticMouse);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticName"), (uintptr_t)&SDL_SYS_HapticName);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticNewEffect"), (uintptr_t)&SDL_SYS_HapticNewEffect);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticOpen"), (uintptr_t)&SDL_SYS_HapticOpen);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticOpenFromJoystick"), (uintptr_t)&SDL_SYS_HapticOpenFromJoystick);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticPause"), (uintptr_t)&SDL_SYS_HapticPause);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticQuit"), (uintptr_t)&SDL_SYS_HapticQuit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticRunEffect"), (uintptr_t)&SDL_SYS_HapticRunEffect);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticSetAutocenter"), (uintptr_t)&SDL_SYS_HapticSetAutocenter);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticSetGain"), (uintptr_t)&SDL_SYS_HapticSetGain);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticStopAll"), (uintptr_t)&SDL_SYS_HapticStopAll);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticStopEffect"), (uintptr_t)&SDL_SYS_HapticStopEffect);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticUnpause"), (uintptr_t)&SDL_SYS_HapticUnpause);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_HapticUpdateEffect"), (uintptr_t)&SDL_SYS_HapticUpdateEffect);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickAttached"), (uintptr_t)&SDL_SYS_JoystickAttached);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickClose"), (uintptr_t)&SDL_SYS_JoystickClose);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickDetect"), (uintptr_t)&SDL_SYS_JoystickDetect);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickGetDeviceGUID"), (uintptr_t)&SDL_SYS_JoystickGetDeviceGUID);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickGetGUID"), (uintptr_t)&SDL_SYS_JoystickGetGUID);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickInit"), (uintptr_t)&SDL_SYS_JoystickInit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickIsHaptic"), (uintptr_t)&SDL_SYS_JoystickIsHaptic);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickNameForDeviceIndex"), (uintptr_t)&SDL_SYS_JoystickNameForDeviceIndex);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickNeedsPolling"), (uintptr_t)&SDL_SYS_JoystickNeedsPolling);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickOpen"), (uintptr_t)&SDL_SYS_JoystickOpen);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickQuit"), (uintptr_t)&SDL_SYS_JoystickQuit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickSameHaptic"), (uintptr_t)&SDL_SYS_JoystickSameHaptic);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_JoystickUpdate"), (uintptr_t)&SDL_SYS_JoystickUpdate);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_NumJoysticks"), (uintptr_t)&SDL_SYS_NumJoysticks);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_SetThreadPriority"), (uintptr_t)&SDL_SYS_SetThreadPriority);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_SetupThread"), (uintptr_t)&SDL_SYS_SetupThread);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SYS_WaitThread"), (uintptr_t)&SDL_SYS_WaitThread);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SaveAllDollarTemplates"), (uintptr_t)&SDL_SaveAllDollarTemplates);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SaveBMP_RW"), (uintptr_t)&SDL_SaveBMP_RW);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SaveDollarTemplate"), (uintptr_t)&SDL_SaveDollarTemplate);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SemPost"), (uintptr_t)&SDL_SemPost);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SemTryWait"), (uintptr_t)&SDL_SemTryWait);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SemValue"), (uintptr_t)&SDL_SemValue);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SemWait"), (uintptr_t)&SDL_SemWait);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SemWaitTimeout"), (uintptr_t)&SDL_SemWaitTimeout);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendClipboardUpdate"), (uintptr_t)&SDL_SendClipboardUpdate);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendDropFile"), (uintptr_t)&SDL_SendDropFile);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendEditingText"), (uintptr_t)&SDL_SendEditingText);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendGestureMulti"), (uintptr_t)&SDL_SendGestureMulti);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendKeyboardKey"), (uintptr_t)&SDL_SendKeyboardKey);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendKeyboardText"), (uintptr_t)&SDL_SendKeyboardText);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendMouseButton"), (uintptr_t)&SDL_SendMouseButton);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendMouseMotion"), (uintptr_t)&SDL_SendMouseMotion);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendMouseWheel"), (uintptr_t)&SDL_SendMouseWheel);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendQuit"), (uintptr_t)&SDL_SendQuit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendSysWMEvent"), (uintptr_t)&SDL_SendSysWMEvent);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendTouch"), (uintptr_t)&SDL_SendTouch);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendTouchMotion"), (uintptr_t)&SDL_SendTouchMotion);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SendWindowEvent"), (uintptr_t)&SDL_SendWindowEvent);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetAssertionHandler"), (uintptr_t)&SDL_SetAssertionHandler);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetClipRect"), (uintptr_t)&SDL_SetClipRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetClipboardText"), (uintptr_t)&SDL_SetClipboardText);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetColorKey"), (uintptr_t)&SDL_SetColorKey);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetCursor"), (uintptr_t)&SDL_SetCursor);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SetDefaultCursor"), (uintptr_t)&SDL_SetDefaultCursor);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetError"), (uintptr_t)&SDL_SetError);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetEventFilter"), (uintptr_t)&SDL_SetEventFilter);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetHint"), (uintptr_t)&SDL_SetHint);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetHintWithPriority"), (uintptr_t)&SDL_SetHintWithPriority);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SetKeyboardFocus"), (uintptr_t)&SDL_SetKeyboardFocus);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SetKeymap"), (uintptr_t)&SDL_SetKeymap);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetModState"), (uintptr_t)&SDL_SetModState);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SetMouseFocus"), (uintptr_t)&SDL_SetMouseFocus);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetPaletteColors"), (uintptr_t)&SDL_SetPaletteColors);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetPixelFormatPalette"), (uintptr_t)&SDL_SetPixelFormatPalette);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetRelativeMouseMode"), (uintptr_t)&SDL_SetRelativeMouseMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetRenderDrawBlendMode"), (uintptr_t)&SDL_SetRenderDrawBlendMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetRenderDrawColor"), (uintptr_t)&SDL_SetRenderDrawColor);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetRenderTarget"), (uintptr_t)&SDL_SetRenderTarget);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_SetScancodeName"), (uintptr_t)&SDL_SetScancodeName);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetSurfaceAlphaMod"), (uintptr_t)&SDL_SetSurfaceAlphaMod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetSurfaceBlendMode"), (uintptr_t)&SDL_SetSurfaceBlendMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetSurfaceColorMod"), (uintptr_t)&SDL_SetSurfaceColorMod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetSurfacePalette"), (uintptr_t)&SDL_SetSurfacePalette);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetSurfaceRLE"), (uintptr_t)&SDL_SetSurfaceRLE);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetTextInputRect"), (uintptr_t)&SDL_SetTextInputRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetTextureAlphaMod"), (uintptr_t)&SDL_SetTextureAlphaMod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetTextureBlendMode"), (uintptr_t)&SDL_SetTextureBlendMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetTextureColorMod"), (uintptr_t)&SDL_SetTextureColorMod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetThreadPriority"), (uintptr_t)&SDL_SetThreadPriority);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowBordered"), (uintptr_t)&SDL_SetWindowBordered);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowBrightness"), (uintptr_t)&SDL_SetWindowBrightness);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowData"), (uintptr_t)&SDL_SetWindowData);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowDisplayMode"), (uintptr_t)&SDL_SetWindowDisplayMode);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowFullscreen"), (uintptr_t)&SDL_SetWindowFullscreen);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowGammaRamp"), (uintptr_t)&SDL_SetWindowGammaRamp);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowGrab"), (uintptr_t)&SDL_SetWindowGrab);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowIcon"), (uintptr_t)&SDL_SetWindowIcon);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowMaximumSize"), (uintptr_t)&SDL_SetWindowMaximumSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowMinimumSize"), (uintptr_t)&SDL_SetWindowMinimumSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowPosition"), (uintptr_t)&SDL_SetWindowPosition);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowShape"), (uintptr_t)&SDL_SetWindowShape);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowSize"), (uintptr_t)&SDL_SetWindowSize);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SetWindowTitle"), (uintptr_t)&SDL_SetWindowTitle);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_ShouldAllowTopmost"), (uintptr_t)&SDL_ShouldAllowTopmost);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ShowCursor"), (uintptr_t)&SDL_ShowCursor);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ShowMessageBox"), (uintptr_t)&SDL_ShowMessageBox);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_ShowProgressHUD"), (uintptr_t)&SDL_ShowProgressHUD);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ShowSimpleMessageBox"), (uintptr_t)&SDL_ShowSimpleMessageBox);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ShowWindow"), (uintptr_t)&SDL_ShowWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_SoftStretch"), (uintptr_t)&SDL_SoftStretch);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_StartEventLoop"), (uintptr_t)&SDL_StartEventLoop);
	hook_addr(so_symbol(&tombraider_mod, "SDL_StartTextInput"), (uintptr_t)&SDL_StartTextInput);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_StartTicks"), (uintptr_t)&SDL_StartTicks);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_StopEventLoop"), (uintptr_t)&SDL_StopEventLoop);
	hook_addr(so_symbol(&tombraider_mod, "SDL_StopTextInput"), (uintptr_t)&SDL_StopTextInput);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ThreadID"), (uintptr_t)&SDL_ThreadID);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_TimerInit"), (uintptr_t)&SDL_TimerInit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_TimerQuit"), (uintptr_t)&SDL_TimerQuit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_TouchInit"), (uintptr_t)&SDL_TouchInit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_TouchQuit"), (uintptr_t)&SDL_TouchQuit);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_TraverseShapeTree"), (uintptr_t)&SDL_TraverseShapeTree);
	hook_addr(so_symbol(&tombraider_mod, "SDL_TryLockMutex"), (uintptr_t)&SDL_TryLockMutex);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_UnRLESurface"), (uintptr_t)&SDL_UnRLESurface);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_UninstallParachute"), (uintptr_t)&SDL_UninstallParachute);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UnionRect"), (uintptr_t)&SDL_UnionRect);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UnloadObject"), (uintptr_t)&SDL_UnloadObject);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UnlockAudio"), (uintptr_t)&SDL_UnlockAudio);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UnlockAudioDevice"), (uintptr_t)&SDL_UnlockAudioDevice);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UnlockMutex"), (uintptr_t)&SDL_UnlockMutex);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UnlockSurface"), (uintptr_t)&SDL_UnlockSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UnlockTexture"), (uintptr_t)&SDL_UnlockTexture);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UpdateTexture"), (uintptr_t)&SDL_UpdateTexture);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_UpdateWindowGrab"), (uintptr_t)&SDL_UpdateWindowGrab);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UpdateWindowSurface"), (uintptr_t)&SDL_UpdateWindowSurface);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UpdateWindowSurfaceRects"), (uintptr_t)&SDL_UpdateWindowSurfaceRects);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UpperBlit"), (uintptr_t)&SDL_UpperBlit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_UpperBlitScaled"), (uintptr_t)&SDL_UpperBlitScaled);
	//hook_addr(so_symbol(&tombraider_mod, "SDL_Vibrate"), (uintptr_t)&SDL_Vibrate);
	hook_addr(so_symbol(&tombraider_mod, "SDL_VideoInit"), (uintptr_t)&SDL_VideoInit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_VideoQuit"), (uintptr_t)&SDL_VideoQuit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WaitEvent"), (uintptr_t)&SDL_WaitEvent);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WaitEventTimeout"), (uintptr_t)&SDL_WaitEventTimeout);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WaitThread"), (uintptr_t)&SDL_WaitThread);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WarpMouseInWindow"), (uintptr_t)&SDL_WarpMouseInWindow);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WasInit"), (uintptr_t)&SDL_WasInit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WriteBE16"), (uintptr_t)&SDL_WriteBE16);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WriteBE32"), (uintptr_t)&SDL_WriteBE32);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WriteBE64"), (uintptr_t)&SDL_WriteBE64);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WriteLE16"), (uintptr_t)&SDL_WriteLE16);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WriteLE32"), (uintptr_t)&SDL_WriteLE32);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WriteLE64"), (uintptr_t)&SDL_WriteLE64);
	hook_addr(so_symbol(&tombraider_mod, "SDL_WriteU8"), (uintptr_t)&SDL_WriteU8);
	hook_addr(so_symbol(&tombraider_mod, "SDL_abs"), (uintptr_t)&SDL_abs);
	hook_addr(so_symbol(&tombraider_mod, "SDL_atof"), (uintptr_t)&SDL_atof);
	hook_addr(so_symbol(&tombraider_mod, "SDL_atoi"), (uintptr_t)&SDL_atoi);
	hook_addr(so_symbol(&tombraider_mod, "SDL_calloc"), (uintptr_t)&SDL_calloc);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ceil"), (uintptr_t)&SDL_ceil);
	hook_addr(so_symbol(&tombraider_mod, "SDL_cosf"), (uintptr_t)&SDL_cosf);
	hook_addr(so_symbol(&tombraider_mod, "SDL_free"), (uintptr_t)&SDL_free);
	hook_addr(so_symbol(&tombraider_mod, "SDL_getenv"), (uintptr_t)&SDL_getenv);
	hook_addr(so_symbol(&tombraider_mod, "SDL_iconv"), (uintptr_t)&SDL_iconv);
	hook_addr(so_symbol(&tombraider_mod, "SDL_iconv_close"), (uintptr_t)&SDL_iconv_close);
	hook_addr(so_symbol(&tombraider_mod, "SDL_iconv_open"), (uintptr_t)&SDL_iconv_open);
	hook_addr(so_symbol(&tombraider_mod, "SDL_iconv_string"), (uintptr_t)&SDL_iconv_string);
	hook_addr(so_symbol(&tombraider_mod, "SDL_isdigit"), (uintptr_t)&SDL_isdigit);
	hook_addr(so_symbol(&tombraider_mod, "SDL_isspace"), (uintptr_t)&SDL_isspace);
	hook_addr(so_symbol(&tombraider_mod, "SDL_itoa"), (uintptr_t)&SDL_itoa);
	hook_addr(so_symbol(&tombraider_mod, "SDL_lltoa"), (uintptr_t)&SDL_lltoa);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ltoa"), (uintptr_t)&SDL_ltoa);
	hook_addr(so_symbol(&tombraider_mod, "SDL_malloc"), (uintptr_t)&SDL_malloc);
	hook_addr(so_symbol(&tombraider_mod, "SDL_memcmp"), (uintptr_t)&SDL_memcmp);
	hook_addr(so_symbol(&tombraider_mod, "SDL_memcpy"), (uintptr_t)&SDL_memcpy);
	hook_addr(so_symbol(&tombraider_mod, "SDL_memmove"), (uintptr_t)&SDL_memmove);
	hook_addr(so_symbol(&tombraider_mod, "SDL_memset"), (uintptr_t)&SDL_memset);
	hook_addr(so_symbol(&tombraider_mod, "SDL_qsort"), (uintptr_t)&SDL_qsort);
	hook_addr(so_symbol(&tombraider_mod, "SDL_realloc"), (uintptr_t)&SDL_realloc);
	hook_addr(so_symbol(&tombraider_mod, "SDL_setenv"), (uintptr_t)&SDL_setenv);
	hook_addr(so_symbol(&tombraider_mod, "SDL_sinf"), (uintptr_t)&SDL_sinf);
	hook_addr(so_symbol(&tombraider_mod, "SDL_snprintf"), (uintptr_t)&SDL_snprintf);
	hook_addr(so_symbol(&tombraider_mod, "SDL_sscanf"), (uintptr_t)&SDL_sscanf);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strcasecmp"), (uintptr_t)&SDL_strcasecmp);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strchr"), (uintptr_t)&SDL_strchr);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strcmp"), (uintptr_t)&SDL_strcmp);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strdup"), (uintptr_t)&SDL_strdup);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strlcat"), (uintptr_t)&SDL_strlcat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strlcpy"), (uintptr_t)&SDL_strlcpy);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strlen"), (uintptr_t)&SDL_strlen);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strlwr"), (uintptr_t)&SDL_strlwr);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strncasecmp"), (uintptr_t)&SDL_strncasecmp);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strncmp"), (uintptr_t)&SDL_strncmp);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strrchr"), (uintptr_t)&SDL_strrchr);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strrev"), (uintptr_t)&SDL_strrev);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strstr"), (uintptr_t)&SDL_strstr);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strtod"), (uintptr_t)&SDL_strtod);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strtol"), (uintptr_t)&SDL_strtol);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strtoll"), (uintptr_t)&SDL_strtoll);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strtoul"), (uintptr_t)&SDL_strtoul);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strtoull"), (uintptr_t)&SDL_strtoull);
	hook_addr(so_symbol(&tombraider_mod, "SDL_strupr"), (uintptr_t)&SDL_strupr);
	hook_addr(so_symbol(&tombraider_mod, "SDL_tolower"), (uintptr_t)&SDL_tolower);
	hook_addr(so_symbol(&tombraider_mod, "SDL_toupper"), (uintptr_t)&SDL_toupper);
	hook_addr(so_symbol(&tombraider_mod, "SDL_uitoa"), (uintptr_t)&SDL_uitoa);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ulltoa"), (uintptr_t)&SDL_ulltoa);
	hook_addr(so_symbol(&tombraider_mod, "SDL_ultoa"), (uintptr_t)&SDL_ultoa);
	hook_addr(so_symbol(&tombraider_mod, "SDL_utf8strlcpy"), (uintptr_t)&SDL_utf8strlcpy);
	hook_addr(so_symbol(&tombraider_mod, "SDL_vsnprintf"), (uintptr_t)&SDL_vsnprintf);
	hook_addr(so_symbol(&tombraider_mod, "SDL_wcslcat"), (uintptr_t)&SDL_wcslcat);
	hook_addr(so_symbol(&tombraider_mod, "SDL_wcslcpy"), (uintptr_t)&SDL_wcslcpy);
	hook_addr(so_symbol(&tombraider_mod, "SDL_wcslen"), (uintptr_t)&SDL_wcslen);
}

int main(int argc, char *argv[]) {
	//sceSysmoduleLoadModule(SCE_SYSMODULE_RAZOR_CAPTURE);
	
	SceIoStat st0, st1, st2, st3, st4;
	if (!sceIoGetstat("ux0:app/AUTOPLUG2", &st0) || !sceIoGetstat("ur0:app/AUTOPLUG2", &st1) || !sceIoGetstat("uma0:app/AUTOPLUG2", &st2) || !sceIoGetstat("imc0:app/AUTOPLUG2", &st3) || !sceIoGetstat("xmc0:app/AUTOPLUG2", &st4)) {
		vglInit(0);
		SceMsgDialogUserMessageParam msg_param;
		sceClibMemset(&msg_param, 0, sizeof(SceMsgDialogUserMessageParam));
		msg_param.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_OK;
		msg_param.msg = (const SceChar8*)"The authors of this software (and the vast majority of the Vita dev scene) repudiates AutoPlugin due to the huge amount of problematics it causes. If you want to run this software, please uninstall AutoPlugin.";
		SceMsgDialogParam param;
		sceMsgDialogParamInit(&param);
		param.mode = SCE_MSG_DIALOG_MODE_USER_MSG;
		param.userMsgParam = &msg_param;
		sceMsgDialogInit(&param);
		while (sceMsgDialogGetStatus() != SCE_COMMON_DIALOG_STATUS_FINISHED) {
			vglSwapBuffers(GL_TRUE);
		}
		sceKernelExitProcess(0);
	}
	printf("%X %X %X %X %X\n", st0, st1, st2, st3, st4);
	
	SceAppUtilInitParam init_param;
	SceAppUtilBootParam boot_param;
	memset(&init_param, 0, sizeof(SceAppUtilInitParam));
	memset(&boot_param, 0, sizeof(SceAppUtilBootParam));
	sceAppUtilInit(&init_param, &boot_param);
	
	sceCtrlSetSamplingModeExt(SCE_CTRL_MODE_ANALOG_WIDE);
	uint8_t is_pstv = sceCtrlIsMultiControllerSupported() ? GL_TRUE : GL_FALSE;
	if (!is_pstv) {
		sceTouchSetSamplingState(SCE_TOUCH_PORT_FRONT, SCE_TOUCH_SAMPLING_STATE_START);
	}

	scePowerSetArmClockFrequency(444);
	scePowerSetBusClockFrequency(222);
	scePowerSetGpuClockFrequency(222);
	scePowerSetGpuXbarClockFrequency(166);

	if (check_kubridge() < 0)
		fatal_error("Error: kubridge.skprx is not installed.");

	if (!file_exists("ur0:/data/libshacccg.suprx") && !file_exists("ur0:/data/external/libshacccg.suprx"))
		fatal_error("Error: libshacccg.suprx is not installed.");
	
	// Generating selected game path
	char fname[256];
	int8_t game_idx = 1;
	FILE *f = fopen("ux0:data/tombraider.tmp", "rb");
	if (f) {
		fread(&game_idx, 1, 1, f);
		fclose(f);
		sceIoRemove("ux0:data/tombraider.tmp");
	}
	sprintf(DATA_PATH, "ux0:data/tombraider/tombraider%d", game_idx);
	
	printf("Loading libmain\n");
	sprintf(fname, "%s/libmain.so", DATA_PATH);
	if (so_file_load(&tombraider_mod, fname, LOAD_ADDRESS) < 0)
		fatal_error("Error could not load %s.", fname);
	so_relocate(&tombraider_mod);
	so_resolve(&tombraider_mod, default_dynlib, sizeof(default_dynlib), 0);
	
	patch_game();
	so_flush_caches(&tombraider_mod);
	so_initialize(&tombraider_mod);
	
	vglInitExtended(0, SCREEN_W, SCREEN_H, MEMORY_VITAGL_THRESHOLD_MB * 1024 * 1024, SCE_GXM_MULTISAMPLE_4X);
	
	memset(fake_vm, 'A', sizeof(fake_vm));
	*(uintptr_t *)(fake_vm + 0x00) = (uintptr_t)fake_vm; // just point to itself...
	*(uintptr_t *)(fake_vm + 0x10) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_vm + 0x14) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_vm + 0x18) = (uintptr_t)GetEnv;

	memset(fake_env, 'A', sizeof(fake_env));
	*(uintptr_t *)(fake_env + 0x00) = (uintptr_t)fake_env; // just point to itself...
	*(uintptr_t *)(fake_env + 0x18) = (uintptr_t)FindClass;
	*(uintptr_t *)(fake_env + 0x54) = (uintptr_t)NewGlobalRef;
	*(uintptr_t *)(fake_env + 0x58) = (uintptr_t)DeleteGlobalRef;
	*(uintptr_t *)(fake_env + 0x5C) = (uintptr_t)ret0; // DeleteLocalRef
	*(uintptr_t *)(fake_env + 0x74) = (uintptr_t)NewObjectV;
	*(uintptr_t *)(fake_env + 0x7C) = (uintptr_t)GetObjectClass;
	*(uintptr_t *)(fake_env + 0x84) = (uintptr_t)GetMethodID;
	*(uintptr_t *)(fake_env + 0x8C) = (uintptr_t)CallObjectMethodV;
	*(uintptr_t *)(fake_env + 0x98) = (uintptr_t)CallBooleanMethodV;
	*(uintptr_t *)(fake_env + 0xD4) = (uintptr_t)CallLongMethodV;
	*(uintptr_t *)(fake_env + 0xF8) = (uintptr_t)CallVoidMethodV;
	*(uintptr_t *)(fake_env + 0x178) = (uintptr_t)GetFieldID;
	*(uintptr_t *)(fake_env + 0x17C) = (uintptr_t)GetBooleanField;
	*(uintptr_t *)(fake_env + 0x190) = (uintptr_t)GetIntField;
	*(uintptr_t *)(fake_env + 0x198) = (uintptr_t)GetFloatField;
	*(uintptr_t *)(fake_env + 0x1C4) = (uintptr_t)GetStaticMethodID;
	*(uintptr_t *)(fake_env + 0x1CC) = (uintptr_t)CallStaticObjectMethodV;
	*(uintptr_t *)(fake_env + 0x1D8) = (uintptr_t)CallStaticBooleanMethodV;
	*(uintptr_t *)(fake_env + 0x208) = (uintptr_t)CallStaticIntMethodV;
	*(uintptr_t *)(fake_env + 0x21C) = (uintptr_t)CallStaticLongMethodV;
	*(uintptr_t *)(fake_env + 0x220) = (uintptr_t)CallStaticFloatMethodV;
	*(uintptr_t *)(fake_env + 0x238) = (uintptr_t)CallStaticVoidMethodV;
	*(uintptr_t *)(fake_env + 0x240) = (uintptr_t)GetStaticFieldID;
	*(uintptr_t *)(fake_env + 0x244) = (uintptr_t)GetStaticObjectField;
	*(uintptr_t *)(fake_env + 0x29C) = (uintptr_t)NewStringUTF;
	*(uintptr_t *)(fake_env + 0x2A0) = (uintptr_t)GetStringUTFLength;
	*(uintptr_t *)(fake_env + 0x2A4) = (uintptr_t)GetStringUTFChars;
	*(uintptr_t *)(fake_env + 0x2A8) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_env + 0x36C) = (uintptr_t)GetJavaVM;
	*(uintptr_t *)(fake_env + 0x374) = (uintptr_t)GetStringUTFRegion;
	
	// Disabling rearpad
	SDL_setenv("VITA_DISABLE_TOUCH_BACK", "1", 1);
	
	void (*nativeDrawFrame) (void *env, void *unk, int unk2) = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider2classic_SDLActivity_nativeDrawFrame");
	int (*requestFMV) () = NULL;
	void (*onNativeJoystickButton) (void *env, void *unk, uint32_t idx, int val);
	void (*onNativeJoystickConnected) (void *env, void *unk, int dev_id, int subdev_id, int val);
	void (*onNativeJoystickAxisMoved) (void *env, void *unk, int idx, int axisX, int axisY);
	void (*JNI_OnLoad) (void *env) = so_symbol(&tombraider_mod, "JNI_OnLoad");
	
	// Tomb Raider 1 FMVs
	const char *fmvs[] = {
		"CAFE",
		"MANSION",
		"SNOW",
		"LIFT",
		"VISION",
		"CANYON",
		"PYRAMID",
		"PRISON",
		"END",
		"",
		"ESCAPE"
	};
	
	if (!nativeDrawFrame) { // Tomb Raider 1
		nativeDrawFrame = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider1classic_SDLActivity_nativeDrawFrame");
		requestFMV = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider1classic_SDLActivity_requestFMV");
		onNativeJoystickButton = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider1classic_SDLActivity_onNativeJoystickButton");
		onNativeJoystickConnected = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider1classic_SDLActivity_onNativeJoystickConnected");
		onNativeJoystickAxisMoved = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider1classic_SDLActivity_onNativeJoystickAxisMoved");
		
		// Set Language
		void (*setLanguage) (int id) = so_symbol(&tombraider_mod, "SetLanguage");
		int lang = -1;
		sceAppUtilSystemParamGetInt(SCE_SYSTEM_PARAM_ID_LANG, &lang);
		switch (lang) {
		case SCE_SYSTEM_PARAM_LANG_FRENCH:
			setLanguage(1);
			break;
		case SCE_SYSTEM_PARAM_LANG_GERMAN:
			setLanguage(2);
			break;
		case SCE_SYSTEM_PARAM_LANG_ITALIAN:
			setLanguage(3);
			break;
		case SCE_SYSTEM_PARAM_LANG_SPANISH:
			setLanguage(4);
			break;
		case SCE_SYSTEM_PARAM_LANG_DUTCH:
			setLanguage(5);
			break;
		case SCE_SYSTEM_PARAM_LANG_PORTUGUESE_BR:
			setLanguage(7);
			break;
		case SCE_SYSTEM_PARAM_LANG_PORTUGUESE_PT:
			setLanguage(6);
			break;
		case SCE_SYSTEM_PARAM_LANG_FINNISH:
			setLanguage(10);
			break;
		default:
			setLanguage(0);
			break;
		}
	} else { // Tomb Raider 2
		nativeDrawFrame = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider2classic_SDLActivity_nativeDrawFrame");
		onNativeJoystickButton = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider2classic_SDLActivity_onNativeJoystickButton");
		onNativeJoystickConnected = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider2classic_SDLActivity_onNativeJoystickConnected");
		onNativeJoystickAxisMoved = so_symbol(&tombraider_mod, "Java_com_squareenix_tombraider2classic_SDLActivity_onNativeJoystickAxisMoved");
	}
	
	uint32_t toXb[] = {13, 11, 10, 12, 0, 1, 2, 3, 4, 5, 0, 8, 14, 9, 15, 7, 6};
	uint32_t btn_map[] = {
		SCE_CTRL_TRIANGLE,
		SCE_CTRL_CIRCLE,
		SCE_CTRL_CROSS,
		SCE_CTRL_SQUARE,
		SCE_CTRL_UP,
		SCE_CTRL_DOWN,
		SCE_CTRL_LEFT,
		SCE_CTRL_RIGHT,
		SCE_CTRL_START,
		SCE_CTRL_SELECT,
		0,
		SCE_CTRL_L1,
		SCE_CTRL_L2,
		SCE_CTRL_R1,
		SCE_CTRL_R2,
		SCE_CTRL_R3,
		SCE_CTRL_L3,
		0
	};
	uint32_t oldpad;

	JNI_OnLoad(fake_env);
	for (;;) {
		// Game logic update
		SceCtrlData pad;
		nativeDrawFrame(fake_env, NULL, 0);
		onNativeJoystickConnected(fake_env, NULL, 10, 1, 1);
		
		// Handle videos (Tomb Raider 1 only)
		int fmv_idx = requestFMV ? requestFMV() : 0;
		if (fmv_idx) {
			char fmv_path[256];
			sprintf(fmv_path, "%s/%s_VITA.mp4", DATA_PATH, fmvs[fmv_idx - 1]);
			playMovie(fmv_path);
			while (getMovieState() != PLAYER_INACTIVE) {
				sceCtrlPeekBufferPositiveExt2(0, &pad, 1);
				if (pad.buttons)
					stopMovie();
				vglSwapBuffers(GL_FALSE);
			}
		}
		
		// Handle controls
		sceCtrlPeekBufferPositiveExt2(0, &pad, 1);
		if (!is_pstv) {
			// Rearpad support for L2/R2/L3/R3 emulation
			SceTouchData touch;
			sceTouchPeek(SCE_TOUCH_PORT_FRONT, &touch, 1);
			for (int j = 0; j < touch.reportNum; j++) {
				int x = touch.report[j].x;
				int y = touch.report[j].y;
				if (x > 960) {
					if (y > 544) {
						pad.buttons |= SCE_CTRL_R3;
					} else {
						pad.buttons |= SCE_CTRL_R2;
					}
				} else {
					if (y > 544) {
						pad.buttons |= SCE_CTRL_L3;
					} else {
						pad.buttons |= SCE_CTRL_L2;
					}
				}
			}
		}
		if (pad.buttons != oldpad) {
			for (int i = 0; i < sizeof(btn_map) / sizeof(*btn_map); i++) {
				if (btn_map[i]) {
					int val = pad.buttons & btn_map[i] ? 1 : 0;
					int old_val = oldpad & btn_map[i] ? 1 : 0;
					if (old_val != val) {
						onNativeJoystickButton(fake_env, NULL, toXb[i], val);
					}
				}
			}
		}
		onNativeJoystickAxisMoved(fake_env, NULL, 0, (int)pad.lx * 257, (int)pad.ly * 257);
		onNativeJoystickAxisMoved(fake_env, NULL, 1, (int)pad.rx * 257, (int)pad.ry * 257);
		oldpad = pad.buttons;
		
		// Buffer swap
		vglSwapBuffers(GL_FALSE);
	}
	
	return 0;
}
