#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "runtime_trace.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, event_sequence_t );
} event_sequence_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} time_map SEC(".maps");

const volatile __u32 traced_cpu = 0;

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next) {

    event_sequence_t *seq;
    u64 *stime;
    u32 index = 0;
    u32 cpuid;

    cpuid = next->wake_cpu;

    if (cpuid != traced_cpu) {
	return 0;
    }

    u64 ts = bpf_ktime_get_ns();

    seq = bpf_map_lookup_elem(&event_sequence_map, &index);
    stime = bpf_map_lookup_elem(&time_map, &index);

    if (!seq || !stime) {
	return -1;
    }

    if (*stime == 0) {
	*stime = ts;
	return 0;
    } else {
	if (seq->curr_event < NUM_EVENTS) {
		seq->events[seq->curr_event & (NUM_EVENTS - 1)].runtime = ts - *stime;
		seq->events[seq->curr_event & (NUM_EVENTS - 1)].runtime /= 1000;
		seq->events[seq->curr_event & (NUM_EVENTS - 1)].pid = prev->pid;
		seq->events[seq->curr_event & (NUM_EVENTS - 1)].tgid = prev->tgid;
		memcpy(seq->events[seq->curr_event & (NUM_EVENTS - 1)].comm, prev->comm, 16);
 		*stime = ts;
    		seq->curr_event++;
	}
    } 

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
