#ifndef __RUNTIME_TRACE_H
#define __RUNTIME_TRACE_H

#define NUM_EVENTS 131072

typedef struct event {
    __u32 pid;
    __u32 tgid;
    __u32 runtime;
    char comm[16];
} event_t;

typedef struct event_sequence {
    event_t events[NUM_EVENTS];
    __u64 curr_event;
} event_sequence_t;

#endif // __RUNTIME_TRACE_H
