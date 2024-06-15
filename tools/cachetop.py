#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# cachetop      Count cache kernel function calls per processes
#               For Linux, uses BCC, eBPF.
#
# USAGE: cachetop
# Taken from cachestat by Brendan Gregg
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jul-2016   Emmanuel Bretelle first version

from __future__ import absolute_import
from __future__ import division
# Do not import unicode_literals until #623 is fixed
# from __future__ import unicode_literals
from __future__ import print_function

from bcc import BPF
from collections import defaultdict
from time import strftime

import argparse
import curses
import pwd
import re
import signal
from time import sleep

FIELDS = (
    "PID",
    "UID",
    "PIDNS",
    "MNTNS",
    "CMD",
    "DIRTIES"
)
#DEFAULT_FIELD = "HITS"
DEFAULT_FIELD = "DIRTIES"
DEFAULT_SORT_FIELD = FIELDS.index(DEFAULT_FIELD)

# signal handler
def signal_ignore(signal, frame):
    print()


# Function to gather data from /proc/meminfo
# return dictionary for quicker lookup of both values
def get_meminfo():
    result = {}

    for line in open('/proc/meminfo'):
        k = line.split(':', 3)
        v = k[1].split()
        result[k[0]] = int(v[0])
    return result


def get_processes_stats(
        bpf,
        sort_field=DEFAULT_SORT_FIELD,
        sort_reverse=False):
    '''
    Return a tuple containing:
    buffer
    cached
    list of tuple with per process cache stats
    '''
    counts = bpf.get_table("counts")
    stats = defaultdict(lambda: defaultdict(int))
    for k, v in counts.items():
        stats["%d-%d-%d-%d-%s" % (k.pid, k.uid, k.pidns, k.mntns, k.comm.decode('utf-8', 'replace'))][k.ip] = v.value
    stats_list = []

    for pid, count in sorted(stats.items(), key=lambda stat: stat[0]):
        mbd = 0

        for k, v in count.items():
            if re.match(b'__set_page_dirty', bpf.ksym(k)) is not None:
                mbd = max(0, v)

        _pid, uid, pidns, mntns, comm = pid.split('-', 4)
        stats_list.append(
            (int(_pid), uid, pidns, mntns, comm, mbd))

    stats_list = sorted(
        stats_list, key=lambda stat: stat[sort_field], reverse=sort_reverse
    )
    counts.clear()
    return stats_list


def handle_loop(stdscr, args):
    # don't wait on key press
    stdscr.nodelay(1)
    # set default sorting field
    sort_field = FIELDS.index(DEFAULT_FIELD)
    sort_reverse = True

    # load BPF program
    bpf_text = """

    #include <uapi/linux/ptrace.h>
    #include <linux/nsproxy.h>
    #include <linux/ns_common.h>
    #include <linux/sched.h>
    #include <linux/pid_namespace.h>
    #include <linux/mount.h>
    #include <linux/fs.h>

    /* see mountsnoop.py:
    * XXX: struct mnt_namespace is defined in fs/mount.h, which is private
    * to the VFS and not installed in any kernel-devel packages. So, let's
    * duplicate the important part of the definition. There are actually
    * more members in the real struct, but we don't need them, and they're
    * more likely to change.
    */
    struct mnt_namespace {
        atomic_t count;
        struct ns_common ns;
    };

    struct key_t {
        u64 ip;
        u32 pid;
        u32 uid;
        u64 pidns;
        u64 mntns;
        char comm[16];
    };

    BPF_HASH(counts, struct key_t);

    int do_count(struct pt_regs *ctx) {
        struct key_t key = {};
        u64 pid = bpf_get_current_pid_tgid();
        u32 uid = bpf_get_current_uid_gid();

        struct address_space *addr_space = (struct address_space *)PT_REGS_PARM2(ctx);
        struct inode *f_inode = addr_space->host;
        struct super_block *f_sb = f_inode->i_sb;
        u32 dev = f_sb->s_dev;

        struct task_struct *task;

        task = (struct task_struct *)bpf_get_current_task();

        key.ip = PT_REGS_IP(ctx);
        key.pid = pid & 0xFFFFFFFF;
        key.uid = uid & 0xFFFFFFFF;
        key.pidns = task->nsproxy->pid_ns_for_children->ns.inum;
        key.mntns = task->nsproxy->mnt_ns->ns.inum;
        bpf_get_current_comm(&(key.comm), 16);

        if(dev == MKDEV(TARGET_DEV_MAJOR_NUM, TARGET_DEV_MINOR_NUM)){
            counts.increment(key);
        }
        return 0;
    }

    """

    major_num, minor_num = args.dev_num.split(':', 2)
    bpf_text = bpf_text.replace('TARGET_DEV_MAJOR_NUM', major_num)
    bpf_text = bpf_text.replace('TARGET_DEV_MINOR_NUM', minor_num)

    b = BPF(text=bpf_text)
    b.attach_kprobe(event="__set_page_dirty", fn_name="do_count")

    exiting = 0

    while 1:
        s = stdscr.getch()
        if s == ord('q'):
            exiting = 1
        elif s == ord('r'):
            sort_reverse = not sort_reverse
        elif s == ord('<'):
            sort_field = max(0, sort_field - 1)
        elif s == ord('>'):
            sort_field = min(len(FIELDS) - 1, sort_field + 1)
        try:
            sleep(args.interval)
        except KeyboardInterrupt:
            exiting = 1
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        # Get memory info
        mem = get_meminfo()
        cached = int(mem["Cached"]) / 1024
        buff = int(mem["Buffers"]) / 1024

        process_stats = get_processes_stats(
            b,
            sort_field=sort_field,
            sort_reverse=sort_reverse)
        stdscr.clear()
        stdscr.addstr(
            0, 0,
            "%-8s Buffers MB: %.0f / Cached MB: %.0f "
            "/ Sort: %s / Order: %s" % (
                strftime("%H:%M:%S"), buff, cached, FIELDS[sort_field],
                sort_reverse and "descending" or "ascending"
            )
        )

        # header
        stdscr.addstr(
            1, 0,
            "{0:8} {1:8} {2:16} {3:16} {4:16} {5:8}".format(
                *FIELDS
            ),
            curses.A_REVERSE
        )
        (height, width) = stdscr.getmaxyx()
        for i, stat in enumerate(process_stats):
            uid = int(stat[1])
            try:
                username = pwd.getpwuid(uid)[0]
            except KeyError:
                # `pwd` throws a KeyError if the user cannot be found. This can
                # happen e.g. when the process is running in a cgroup that has
                # different users from the host.
                username = 'UNKNOWN({})'.format(uid)

            stdscr.addstr(
                i + 2, 0,
                "{0:8} {username:8.8} {2:16} {3:16} {4:16} {5:8} ".format(
                    *stat, username=username
                )
            )
            if i > height - 4:
                break
        stdscr.refresh()
        if exiting:
            print("Detaching...")
            return


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='show Linux page cache hit/miss statistics including read '
                    'and write hit % per processes in a UI like top.'
    )

    parser.add_argument('dev_num', type=str, default=8, 
                        help='The device number of the storage device.')
    
    parser.add_argument(
        'interval', type=int, default=5, nargs='?', 
        help='Interval between probes.'
    )

    args = parser.parse_args()
    return args

args = parse_arguments()
curses.wrapper(handle_loop, args)
