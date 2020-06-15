#ifndef _SMOKE_BOMB_PATCH_H
#define _SMOKE_BOMB_PATCH_H

int fix_unresolve_function_ptrs(void);
int patch_user_memory(unsigned long sva, unsigned long eva);

void register_ex_handler(void);
void unregister_ex_handler(void);

#endif