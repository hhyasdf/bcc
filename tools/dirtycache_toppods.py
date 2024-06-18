#!/usr/bin/python
# -*- coding: UTF-8 -*-
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

import subprocess
import re
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


PRINT_FIELDS = (
    "POD",
    "DIRTIES"
)

def install_bcc_tools():
    subprocess.call(["yum", "install", "bcc-tools"], shell=False)


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
    return stats_list


def load_bpf(dev_num):
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

    major_num, minor_num = dev_num.split(':', 2)
    bpf_text = bpf_text.replace('TARGET_DEV_MAJOR_NUM', major_num)
    bpf_text = bpf_text.replace('TARGET_DEV_MINOR_NUM', minor_num)

    b = BPF(text=bpf_text)
    b.attach_kprobe(event="__set_page_dirty", fn_name="do_count")

    return b



def check_mntns_loop(interval, count):
    # 维护一个 mntns id 和 pod name 的关系
    mntnsToPodMap = {}
    execFunc = lambda cmd_str: subprocess.Popen([cmd_str], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True).stdout.read()

    for i in range(count):
        if i == count:
            break

        sleep(interval)

        mntns_list = execFunc("lsns -t mnt | tail -n +2 | awk '{print $1\",\"$4}'").split("\n")
        for mntns_str in mntns_list:
            if mntns_str == "":
                continue

            mntns_id, main_pid = mntns_str.split(",",1)
            pod_name = ""
            
            if mntnsToPodMap.has_key(mntns_id):
                continue

            # 找到 mnt ns 对应的 pod
            cmd_str = "cat /proc/%s/cgroup | awk -F '/' '{print $NF}' | awk 'END {print}' | cut -b 16-22"%main_pid
            container_id = execFunc(cmd_str).strip()

            if container_id != "":
                cmd_str = "crictl inspect -o go-template --template='{{index .status.labels \"io.kubernetes.pod.name\"}}' " + container_id
                pod_name = execFunc(cmd_str).strip()
                if pod_name == "":
                    cmd_str = "crictl pods | grep %s | awk '{print $(NF-3)}'"%container_id
                    pod_name = execFunc(cmd_str).strip()

            mntnsToPodMap[mntns_id] = pod_name    

    return mntnsToPodMap

            
# 运行一段时间（interval * count），输出对特定设备的 page cache 执行 __set_page_dirty 次数 topN 的 pod name，以及次数
if __name__ == "__main__":
    dev_num = "8:16"
    interval = 1
    count = 60
    topN = 10

    # set default sorting field
    sort_field = FIELDS.index(DEFAULT_FIELD)
    sort_reverse = True

    install_bcc_tools()

    print("****************\nStart ebpf probe:")
    b = load_bpf(dev_num)
    
    mntnsToPodMap = check_mntns_loop(interval, count)

    # 输出运行结束时的 page cache 情况
    mem = get_meminfo()
    cached = int(mem["Cached"]) / 1024
    buff = int(mem["Buffers"]) / 1024

    process_stats = get_processes_stats(
        b,
        sort_field=sort_field,
        sort_reverse=sort_reverse)
    
    pod_result_dict = {}
    pod_result_list = []

    # 需要把相同 pod 不同进程的次数合并一下
    for k, stat in enumerate(process_stats):
        mntns_id = stat[3]

        # 没找到对应的 mntns，新创建的容器，由于一秒的间隙没扫到，运行时间较短，先不管
        if not mntnsToPodMap.has_key(mntns_id):
            continue

        podName = mntnsToPodMap[mntns_id]
        if podName == "":
            # 没有找到 mntns 对应的 pod name，可能是 host 进程或者 kata 之类的进程
            podName = "[Unknow + Host]"

        if not pod_result_dict.has_key(podName):
            pod_result_dict[podName] = 0

        pod_result_dict[podName] += stat[5]
    
    for key in pod_result_dict:
        pod_result_list.append((key, pod_result_dict[key]))
    
    pod_result_list = sorted(
        pod_result_list, key=lambda pod_result: pod_result[1], reverse=sort_reverse
    )
    
    print("****************\nThe top %d pods are:\n"%topN)

    print_format_str = "{0:64} {1:8}"
    print(print_format_str.format(*PRINT_FIELDS))

    for iindex, valu in enumerate(pod_result_list):
        if iindex == topN:
            break
        print(print_format_str.format(*valu))