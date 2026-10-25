#pragma once 

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/pid.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rqs.h>
#include <linux/sched/signal.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/kfifo.h>
#include <linux/hashtable.h>

// procfs entry used to view registry from scanner
#define PROC_ENTRY "rqs" 
// procfs entry used to read reports of userland-discoverable pids from rqs-userland 
#define PROC_ENTRY_REPORTING "rqs_report"

#define RQS_REPORT_MAX_BYTES (8u << 20) // limit how much data userland can report at once

// point at which to assume the userland sensor is dead and start to fail over to assume all entries can be found in /proc
#define RQS_SNAPSHOT_TTL (15 * HZ)

#define RQS_MAX_TASKS_WALK (4u << 20) // limit how many nodes to walk in tasks before assuming it's corrupted 

#define RQS_PROC_GRACE_NS   (10ULL * NSEC_PER_SEC)


#define RQS_MODE_WARN   0
#define RQS_MODE_FREEZE 1
#define RQS_MODE_KILL   2
#define RQS_MAX_TARGETS 32

struct rqs_registry_entry {
    pid_t pid;
    pid_t tgid; 
    u64 start_time; 
    char comm[TASK_COMM_LEN]; 
    struct task_struct * task; 
    unsigned int detection_count; // how many times this entry appeared hidden 
    u64 seen_tasks_gen; // scan generation this task was found in tasks* 
    bool enforced; 
    struct hlist_node node; // needed to link to hash table 
};


struct rqs_proc_snapshot {
    u64 generation;
    int max_pid; 
    unsigned long stamp;
    u64 capture_ns; 
    unsigned long *map;
    struct rcu_head rcu;
};

// buffers write from userland until terminating newline is encountered 
struct rqs_report_ctx {
    char *buf;
    size_t len; 
    size_t cap; 
};


// exported from core.c
void rqs_freeze_process(struct task_struct *p); 

