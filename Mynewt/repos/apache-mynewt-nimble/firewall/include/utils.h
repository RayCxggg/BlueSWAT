#ifndef IFW_UTILS_H_
#define IFW_UTILS_H_

#include <stdio.h>

/* timer */
void reset_timer_tick(void);
int get_cur_tick(void);
float tick_to_us(int tick);

#define VNAME(name) (#name)

#define DEBUG_LOG(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)

#define IFW_DEBUG_LOG(fmt, ...) \
    printf("(IFW_DEBUG_LOG) [%s] " fmt "\n", __FILE__, ##__VA_ARGS__)

#endif /* IFW_UTILS_H_ */
