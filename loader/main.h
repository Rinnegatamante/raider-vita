#ifndef __MAIN_H__
#define __MAIN_H__

#include <psp2/touch.h>
#include "config.h"
#include "so_util.h"

int debugPrintf(char *text, ...);

int ret0();

int sceKernelChangeThreadCpuAffinityMask(SceUID thid, int cpuAffinityMask);

SceUID _vshKernelSearchModuleByName(const char *, const void *);

extern SceTouchPanelInfo panelInfoFront, panelInfoBack;

enum {
  PLAYER_INACTIVE,
  PLAYER_ACTIVE,
  PLAYER_STOP,
};

void playMovie(const char *fname);
uint8_t getMovieState();
void stopMovie();

#endif
