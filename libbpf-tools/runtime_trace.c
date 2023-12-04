// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on cpudist(8) from BCC by Brendan Gregg & Dina Goldshtein.
// 8-May-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "runtime_trace.h"
#include "runtime_trace.skel.h"
#include "trace_helpers.h"

static struct env {
	int interval;
	char *output;
	int cpuid;
	int duration;
} env = {
	.interval = 1,
	.output = "trace.txt",
	.cpuid = 0,
	.duration = 10
};

static volatile bool exiting;

const char *argp_program_version = "runtime_trace 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Produce trace of runtime events for a specific core.\n"
"\n"
"USAGE: runtime_trace [--help] [-i interval] [-c core] [-o output] [-d duration]\n"
"\n"
"EXAMPLES:\n"
"    runtime_trace        		# Print trace for CPU core 0 every 1s"
"    cpudist -i 2 -c 10 -o trace_file.txt     # Capture a trace for 2 seconds on core 10 and write to file trace_file.txt";

static const struct argp_option opts[] = {
	{ "interval", 'i', "1", 0, "Trace generation interval in seconds" },
	{ "core", 'c', "0", 0, "CPU core to capture trace" },
	{ "duration", 'd', "10", 0, "Duration of trace capture" },
	{ "output", 'o', "traces.txt", 0, "Millisecond histogram" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		break;
	case 'c':
		env.cpuid = strtol(arg, NULL, 10);
		break;
	case 'd':
		env.duration = strtol(arg, NULL, 10);
		break;
	case 'o':
		env.output = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

int write_event_trace(int fd, FILE* f) {
    event_sequence_t seq = {0};
    event_sequence_t seq2 = {0};
    uint32_t index = 0;

    bpf_map_lookup_elem(fd, &index, &seq);
    bpf_map_update_elem(fd, &index, &seq2, 0);

    for (int i = 0; i < seq.curr_event; i++) {
	fprintf(f, "%s, %d, %d, %d\n", seq.events[i].comm, seq.events[i].tgid, seq.events[i].pid, seq.events[i].runtime);
    }
    return 0;
}

int main(int argc, char **argv)
{
	int runtime = 0;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct runtime_trace_bpf *obj;
	int fd, err;
	FILE *f;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	obj = runtime_trace_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	f = fopen(env.output, "w");

   	if(f == NULL) {
		printf("Error!");
      		exit(1);
	}

	fprintf(f, "name, pid, tid, runtime\n");

	/* initialize global data (filtering options) */
	printf("Will trace CPU %d\n", env.cpuid);
	obj->rodata->traced_cpu = env.cpuid;

	err = runtime_trace_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = runtime_trace_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	fd = bpf_map__fd(obj->maps.event_sequence_map);

	signal(SIGINT, sig_handler);

	printf("Tracing events on CPU %d... Hit Ctrl-C to end.\n", env.cpuid);
	printf("Will trace for %d seconds\n", env.duration);

	/* main: poll */
	while (runtime < env.duration) {
		sleep(env.interval);
		runtime += env.interval;

		err = write_event_trace(fd, f);
		if (err)
			break;

		if (exiting)
			break;
	}

cleanup:
	runtime_trace_bpf__destroy(obj);
	fclose(f);
	return err != 0;
}
