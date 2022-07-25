#include <limits.h>
#include <math.h>
#include <vitasdk.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vitaGL.h>

#include "main.h"
#include "shaders/movie_f.h"
#include "shaders/movie_v.h"

#define FB_ALIGNMENT 0x40000
#define ALIGN_MEM(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

float postfx_pos[8] = {
  -1.0f, 1.0f,
  -1.0f, -1.0f,
   1.0f, 1.0f,
   1.0f, -1.0f
};

float postfx_texcoord[8] = {
  0.0f, 0.0f,
  0.0f, 1.0f,
  1.0f, 0.0f,
  1.0f, 1.0f
};

SceAvPlayerHandle movie_player;

GLuint movie_frame[3];
uint8_t movie_frame_idx = 0;
SceGxmTexture *movie_tex[3];
GLuint movie_fs;
GLuint movie_vs;
GLuint movie_prog;

SceUID audio_thid;
int audio_new;
int audio_port;
int audio_len;
int audio_freq;
int audio_mode;

int player_state = PLAYER_INACTIVE;

void *mem_alloc(void *p, uint32_t align, uint32_t size) {
  return memalign(align, size);
}

void mem_free(void *p, void *ptr) {
  free(ptr);
}

void *gpu_alloc(void *p, uint32_t align, uint32_t size) {
  if (align < FB_ALIGNMENT) {
    align = FB_ALIGNMENT;
  }
  size = ALIGN_MEM(size, align);
  return vglAlloc(size, VGL_MEM_SLOW);
}

void gpu_free(void *p, void *ptr) {
  glFinish();
  vglFree(ptr);
}

void movie_player_audio_init(void) {
  audio_port = -1;
  for (int i = 0; i < 8; i++) {
    if (sceAudioOutGetConfig(i, SCE_AUDIO_OUT_CONFIG_TYPE_LEN) >= 0) {
      audio_port = i;
      break;
    }
  }

  if (audio_port == -1) {
    audio_port = sceAudioOutOpenPort(SCE_AUDIO_OUT_PORT_TYPE_MAIN, 1024, 48000, SCE_AUDIO_OUT_MODE_STEREO);
    audio_new = 1;
  } else {
    audio_len = sceAudioOutGetConfig(audio_port, SCE_AUDIO_OUT_CONFIG_TYPE_LEN);
    audio_freq = sceAudioOutGetConfig(audio_port, SCE_AUDIO_OUT_CONFIG_TYPE_FREQ);
    audio_mode = sceAudioOutGetConfig(audio_port, SCE_AUDIO_OUT_CONFIG_TYPE_MODE);
    audio_new = 0;
  }
}

void movie_player_audio_shutdown(void) {
  if (audio_new) {
    sceAudioOutReleasePort(audio_port);
  } else {
    sceAudioOutSetConfig(audio_port, audio_len, audio_freq, (SceAudioOutMode)audio_mode);
  }
}

int movie_player_audio_thread(SceSize args, void *argp) {
  SceAvPlayerFrameInfo frame;
  memset(&frame, 0, sizeof(SceAvPlayerFrameInfo));

  while (player_state == PLAYER_ACTIVE && sceAvPlayerIsActive(movie_player)) {
    if (sceAvPlayerGetAudioData(movie_player, &frame)) {
      sceAudioOutSetConfig(audio_port, 1024, frame.details.audio.sampleRate, frame.details.audio.channelCount == 1 ? SCE_AUDIO_OUT_MODE_MONO : SCE_AUDIO_OUT_MODE_STEREO);
      sceAudioOutOutput(audio_port, frame.pData);
    } else {
      sceKernelDelayThread(1000);
    }
  }

  return sceKernelExitDeleteThread(0);
}

int movie_first_frame_drawn;
void movie_player_draw(void) {
  if (player_state == PLAYER_ACTIVE) {
    if (sceAvPlayerIsActive(movie_player)) {
      SceAvPlayerFrameInfo frame;
      if (sceAvPlayerGetVideoData(movie_player, &frame)) {
        movie_first_frame_drawn = 1;
        movie_frame_idx = (movie_frame_idx + 1) % 3;
        sceGxmTextureInitLinear(
          movie_tex[movie_frame_idx],
          frame.pData,
          SCE_GXM_TEXTURE_FORMAT_YVU420P2_CSC1,
          frame.details.video.width,
          frame.details.video.height, 0);
        sceGxmTextureSetMinFilter(movie_tex[movie_frame_idx], SCE_GXM_TEXTURE_FILTER_LINEAR);
        sceGxmTextureSetMagFilter(movie_tex[movie_frame_idx], SCE_GXM_TEXTURE_FILTER_LINEAR);
      }
	  glClear(GL_COLOR_BUFFER_BIT);
      if (movie_first_frame_drawn) {
        glUseProgram(movie_prog);
        glBindTexture(GL_TEXTURE_2D, movie_frame[movie_frame_idx]);
        glBindBuffer(GL_ARRAY_BUFFER, 0);
        glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
        glEnableVertexAttribArray(0);
        glEnableVertexAttribArray(1);
        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, &postfx_pos[0]);
        glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 0, &postfx_texcoord[0]);
        glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
      }
    } else {
      player_state = PLAYER_STOP;
    }
  }

  if (player_state == PLAYER_STOP) {
    sceAvPlayerStop(movie_player);
    sceKernelWaitThreadEnd(audio_thid, NULL, NULL);
    sceAvPlayerClose(movie_player);
    movie_player_audio_shutdown();
    player_state = PLAYER_INACTIVE;
    glClear(GL_COLOR_BUFFER_BIT);
  }
}

int movie_player_inited = 0;
void movie_player_init() {
  if (movie_player_inited)
    return;

  sceSysmoduleLoadModule(SCE_SYSMODULE_AVPLAYER);

  glGenTextures(3, movie_frame);
  for (int i = 0; i < 3; i++) {
    glBindTexture(GL_TEXTURE_2D, movie_frame[i]);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 960, 544, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
    movie_tex[i] = vglGetGxmTexture(GL_TEXTURE_2D);
    vglFree(vglGetTexDataPointer(GL_TEXTURE_2D));
  }
  
  movie_vs = glCreateShader(GL_VERTEX_SHADER);
  glShaderBinary(1, &movie_vs, 0, movie_v, size_movie_v);

  movie_fs = glCreateShader(GL_FRAGMENT_SHADER);
  glShaderBinary(1, &movie_fs, 0, movie_f, size_movie_f);

  movie_prog = glCreateProgram();
  glAttachShader(movie_prog, movie_vs);
  glAttachShader(movie_prog, movie_fs);
  glBindAttribLocation(movie_prog, 0, "inPos");
  glBindAttribLocation(movie_prog, 1, "inTex");
  glLinkProgram(movie_prog);

  movie_player_inited = 1;
}


void playMovie(const char *fname) {
  SceIoStat st;
  if (sceIoGetstat(fname, &st) < 0)
    return;

  movie_player_init();
  movie_player_audio_init();

  SceAvPlayerInitData playerInit;
  sceClibMemset(&playerInit, 0, sizeof(SceAvPlayerInitData));

  playerInit.memoryReplacement.allocate = mem_alloc;
  playerInit.memoryReplacement.deallocate = mem_free;
  playerInit.memoryReplacement.allocateTexture = gpu_alloc;
  playerInit.memoryReplacement.deallocateTexture = gpu_free;

  playerInit.basePriority = 0xA0;
  playerInit.numOutputVideoFrameBuffers = 3;
  playerInit.autoStart = GL_TRUE;
  //playerInit.debugLevel = 3;

  movie_player = sceAvPlayerInit(&playerInit);

  sceAvPlayerAddSource(movie_player, fname);

  audio_thid = sceKernelCreateThread("movie_audio_thread", movie_player_audio_thread, 0x10000100 - 10, 0x4000, 0, 0, NULL);
  sceKernelStartThread(audio_thid, 0, NULL);

  player_state = PLAYER_ACTIVE;
  movie_first_frame_drawn = 0;
}

void stopMovie() {
  player_state = PLAYER_STOP;
}

uint8_t getMovieState() {
  movie_player_draw();
  if (!(player_state == PLAYER_ACTIVE && sceAvPlayerIsActive(movie_player)))
    return 0;
  return 1;
}
