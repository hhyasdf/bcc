#!/usr/bin/python
# -*- coding: UTF-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# iowaithigh    Trace long process scheduling delays.
#               For Linux, uses BCC, eBPF.
#
# This script traces high scheduling delays between tasks being
# ready to run and them running on CPU after that.
#
# USAGE: iowaithigh [min_us]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
#
# This measures the time a task spends waiting on a run queue for a turn
# on-CPU, and shows this time as a individual events. This time should be small,
# but a task may need to wait its turn due to CPU load.
#
# This measures two types of run queue latency:
# 1. The time from a task being enqueued on a run queue to its context switch
#    and execution. This traces ttwu_do_wakeup(), wake_up_new_task() ->
#    finish_task_switch() with either raw tracepoints (if supported) or kprobes
#    and instruments the run queue latency after a voluntary context switch.
# 2. The time from when a task was involuntary context switched and still
#    in the runnable state, to when it next executed. This is instrumented
#    from finish_task_switch() alone.
#
# Copyright 2016 Cloudflare, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 02-May-2018   Ivan Babrou   Created this.
# 18-Nov-2019   Gergely Bod   BUG fix: Use bpf_probe_read_kernel_str() to extract the
#                               process name from 'task_struct* next' in raw tp code.
#                               bpf_get_current_comm() operates on the current task
#                               which might already be different than 'next'.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./iowaithigh         # trace run queue latency higher than 10000 us (default)
    ./iowaithigh 1000    # trace run queue latency higher than 1000 us
"""
parser = argparse.ArgumentParser(
    description="Trace high run queue latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("min_us", nargs="?", default='10000',
    help="minimum run queue latency to trace, in us (default 10000)")

args = parser.parse_args()

min_us = int(args.min_us)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

BPF_HASH(start, u32);

struct rq;

struct data_t {
    u32 pid;
    char task[TASK_COMM_LEN];
    u64 delta_us;
};

struct task_info {
    unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_remote_wakeup: 1;
	unsigned int: 0;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	long unsigned int atomic_flags;
};

BPF_PERF_OUTPUT(events);

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid;
    struct task_info ti;
    long state;

    // ivcsw: treat like an enqueue event and store timestamp
    // bpf_probe_read_kernel() 没法读取 bit-field 字段，只能直接定义一部分 task_struct，然后把一些字段挖出来，这样好像可以不用管大小字节序
    bpf_probe_read_kernel(&ti, sizeof(struct task_info), (struct task_info *)&prev->personality);
    bpf_probe_read_kernel(&state, sizeof(long), (const void *)&prev->state);

    if (ti.in_iowait && state == TASK_UNINTERRUPTIBLE) {
        bpf_probe_read_kernel(&pid, sizeof(prev->pid), &prev->pid);
        u64 ts = bpf_ktime_get_ns();
        if (pid != 0) {
            start.update(&pid, &ts);
        }
    }

    bpf_probe_read_kernel(&pid, sizeof(next->pid), &next->pid);

    u64 *tsp, delta_us;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    if (FILTER_US)
        return 0;

    struct data_t data = {};
    data.pid = pid;
    data.delta_us = delta_us;
    bpf_probe_read_kernel_str(&data.task, sizeof(data.task), next->comm);

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    start.delete(&pid);
    return 0;
}
"""

# code substitutions
if min_us == 0:
    bpf_text = bpf_text.replace('FILTER_US', '0')
else:
    bpf_text = bpf_text.replace('FILTER_US', 'delta_us <= %s' % str(min_us))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-8s %-16s %-6s %14s" % (strftime("%H:%M:%S"), event.task, event.pid, event.delta_us))

# load BPF program
b = BPF(text=bpf_text)

print("Tracing run queue latency higher than %d us" % min_us)
print("%-8s %-16s %-6s %14s" % ("TIME", "COMM", "TID", "LAT(us)"))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
