#include <vitasdk.h>
#include <kubridge.h>
#include <vitashark.h>
#include <vitaGL.h>
#include "../loader/dialog.h"

#include <malloc.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <wchar.h>
#include <wctype.h>

#define STB_IMAGE_IMPLEMENTATION
#define STB_ONLY_PNG
#include "stb_image.h"

#define SCREEN_W 960
#define SCREEN_H 544

void *__wrap_memcpy(void *dest, const void *src, size_t n) {
	return sceClibMemcpy(dest, src, n);
}

void *__wrap_memmove(void *dest, const void *src, size_t n) {
	return sceClibMemmove(dest, src, n);
}

void *__wrap_memset(void *s, int c, size_t n) {
	return sceClibMemset(s, c, n);
}

int file_exists(const char *path) {
	SceIoStat stat;
	return sceIoGetstat(path, &stat) >= 0;
}

int check_kubridge(void) {
	int search_unk[2];
	return _vshKernelSearchModuleByName("kubridge", search_unk);
}

int main(int argc, char *argv[]) {
	scePowerSetArmClockFrequency(444);
	scePowerSetBusClockFrequency(222);
	scePowerSetGpuClockFrequency(222);
	scePowerSetGpuXbarClockFrequency(166);
	
	if (check_kubridge() < 0)
		fatal_error("Error: kubridge.skprx is not installed.");

	if (!file_exists("ur0:/data/libshacccg.suprx") && !file_exists("ur0:/data/external/libshacccg.suprx"))
		fatal_error("Error: libshacccg.suprx is not installed.");
	
	vglInitExtended(0, SCREEN_W, SCREEN_H, 8 * 1024 * 1024, SCE_GXM_MULTISAMPLE_NONE);
	
	// Setting up game selector
	char fname[256];
	GLuint textures[2];
	glGenTextures(2, textures);
	GLboolean available_games[2] = {GL_FALSE, GL_FALSE, GL_FALSE};
	GLboolean has_at_least_one_game = GL_FALSE;
	
	for (int i = 0; i < 2; i++) {
		sprintf(fname, "ux0:data/tombraider/tombraider%d/libmain.so", i + 1);
		if (file_exists(fname)) {
			glBindTexture(GL_TEXTURE_2D, textures[i]);
			int w, h;
			sprintf(fname, "app0:images/game%d.png", i + 1);
			uint8_t *tex_data = (uint8_t *)stbi_load(fname, &w, &h, NULL, 4);
			glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, tex_data);
			free(tex_data);
			available_games[i] = GL_TRUE;
			has_at_least_one_game = GL_TRUE;
		}
	}
	if (!has_at_least_one_game)
		fatal_error("Error: No games detected.");
	
	// Game Selector main loop
	glEnable(GL_TEXTURE_2D);
	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_TEXTURE_COORD_ARRAY);
	glViewport(0, 0, SCREEN_W, SCREEN_H);
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0, SCREEN_W, SCREEN_H, 0, -1, 1);
	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
	float tex_vertices[] = {
		       0,        0, 0,
		SCREEN_W,        0, 0,
		SCREEN_W, SCREEN_H, 0,
		       0, SCREEN_H, 0
	};
	float tex_texcoords[] = {0, 0, 1, 0, 1, 1, 0, 1};
	int8_t selector_idx = 0;
	while (!available_games[selector_idx]) {
		selector_idx = (selector_idx + 1) % 2;
	}
	uint32_t oldpad = 0;
	for (;;) {
		SceCtrlData pad;
		sceCtrlPeekBufferPositive(0, &pad, 1);
		if ((pad.buttons & SCE_CTRL_LEFT) && !(oldpad & SCE_CTRL_LEFT)) {
			do {
				selector_idx--;
				if (selector_idx < 0)
					selector_idx = 1;
			} while (!available_games[selector_idx]);
		} else if ((pad.buttons & SCE_CTRL_RIGHT) && !(oldpad & SCE_CTRL_RIGHT)) {
			do {
				selector_idx = (selector_idx + 1) % 2;
			} while (!available_games[selector_idx]);
		} else if ((pad.buttons & SCE_CTRL_CROSS) && !(oldpad & SCE_CTRL_CROSS))
			break;
		oldpad = pad.buttons;
		glBindTexture(GL_TEXTURE_2D, textures[selector_idx]);
		glVertexPointer(3, GL_FLOAT, 0, tex_vertices);
		glTexCoordPointer(2, GL_FLOAT, 0, tex_texcoords);
		glDrawArrays(GL_TRIANGLE_FAN, 0, 4);
		vglSwapBuffers(GL_FALSE);
	}
	
	selector_idx++;
	FILE *f = fopen("ux0:data/tombraider.tmp", "wb+");
	fwrite(&selector_idx, 1, 1, f);
	fclose(f);
	sceAppMgrLoadExec("app0:game.bin", NULL, NULL);
}