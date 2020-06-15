#ifndef _SMOKE_BOMB_API_H
#define _SMOKE_BOMB_API_H

#ifdef __cplusplus
extern "C" {
#endif

void smoke_bomb_init(unsigned int *addr, unsigned long size);
void smoke_bomb_exit(unsigned int *addr, unsigned long size);
void smoke_bomb_manually_init(unsigned int *addr, unsigned long size);
void smoke_bomb_manually_exit(unsigned int *addr, unsigned long size);
inline void smoke_bomb_dummy_init(void)__attribute__((always_inline));
inline void smoke_bomb_dummy_exit(void)__attribute__((always_inline));

#ifdef __cplusplus
}
#endif

#endif
