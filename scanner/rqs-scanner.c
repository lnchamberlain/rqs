#include <linux/init.h>
#include <linux/sched.h>
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
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/sched/signal.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/threads.h>
#include <linux/jiffies.h>
#include <linux/file.h>     
#include <linux/sched/mm.h>  
#include <linux/mm.h>        
#include <linux/dcache.h>    
#include <linux/fs.h>        

#include "rqs-scanner.h"


MODULE_AUTHOR("Logan Chamberlain");
MODULE_DESCRIPTION("RQS scanner - detecting and mitigating hidden processes using the scheduler");
MODULE_LICENSE("GPL"); 
MODULE_VERSION("1.0"); 


static struct proc_dir_entry *proc_entry_registry; 
static struct proc_dir_entry *proc_entry_reporting; 

static struct task_struct *scanner_thread;  

static atomic_t rqs_dropped = ATOMIC_INIT(0);

static u64 rqs_scan_gen = 0; 

static struct task_struct *targets[RQS_MAX_TARGETS]; 

/*
------  COMMAND LINE ARGS SECTION ------
- module takes three arguments:
-- SCANNING_EPOCH - time between scans in seconds 
-- SCAN_KTHREAD - boolean declaring whether kthreads should be excluded from the registry - less scanning overhead but potential blindspot if a kthread is hidden  
-- SCAN_MODE - tristate that can be WARN/FREEZE/KILL - declare enforcement action 
*/

static int SCANNING_EPOCH = 5; 
module_param(SCANNING_EPOCH, int, S_IRUSR | S_IWUSR); 
MODULE_PARM_DESC(SCANNING_EPOCH, "Time between scans in seconds, default=5"); 

static bool SCAN_KTHREADS = true; 
module_param(SCAN_KTHREADS, bool, S_IRUSR | S_IWUSR); 
MODULE_PARM_DESC(SCAN_KTHREADS, "Enable or disable including kthreads in scanner registry, default=true"); 

static int SCAN_MODE = RQS_MODE_WARN; 
module_param(SCAN_MODE, int,  S_IRUSR | S_IWUSR); 
MODULE_PARM_DESC(SCAN_MODE, "Enforcement action: 0=WARN, 1=FREEZE, 2=KILL"); 

static int DETECTION_THRESHOLD = 2; 
module_param(DETECTION_THRESHOLD, int, S_IRUSR | S_IWUSR); 
MODULE_PARM_DESC(DETECTION_THRESHOLD, "How many consecutive epochs a task must appear hidden to trigger enforcement actions, default=2.");

/*
------  DATA STRUCTURE DEFINITION SECTION ------
- uses a kfifo (notification queue), a hash map (registry), and a bitmap (procfs snapshot)
*/

// kfifo buffer the callback function writes into
static DEFINE_KFIFO(rqs_fifo, struct rqs_notification, 1024); 
static DEFINE_RAW_SPINLOCK(rqs_fifo_lock); 

// registry implemented as a hash table - 4096 buckets 
static DEFINE_HASHTABLE(rqs_registry, 12);  
static DEFINE_MUTEX(rqs_registry_lock); 

// procfs enumeration implemented as a bitmap 
static DEFINE_SPINLOCK(rqs_proc_snapshot_lock);
static struct rqs_proc_snapshot __rcu *rqs_proc_snapshot; 
static u64 rqs_report_gen; 

/*
------  CALLBACK FUNCTION SECTION ------
- function invoked by the kernel when notification needs to be passed to the scanner 
*/
static void rqs_scanner_callback(struct rqs_notification *n) 
{
    unsigned long flags; 
    bool queued = false; 

    if (n->type == RQS_NOTIFY_NEW && !n->task) 
        return; 
    // multiple threads could call the callback at the same time, lock needed
    raw_spin_lock_irqsave(&rqs_fifo_lock, flags); 
    if (!kfifo_is_full(&rqs_fifo)) {
        if (n->type == RQS_NOTIFY_NEW)
            get_task_struct(n->task); // fifo entry now owns a ref
        queued = kfifo_put(&rqs_fifo, *n); 
    }
    raw_spin_unlock_irqrestore(&rqs_fifo_lock, flags); 
    if (!queued) {
        atomic_inc(&rqs_dropped);
    }
}

/*
------  MISC HELPER FUNCTION SECTION ------
*/

static struct rqs_registry_entry *rqs_registry_find(struct task_struct *task)
{
   
    // looks up an entry in the registry by task_struct pointer 
    struct rqs_registry_entry *e;
    // caller must hold rqs_registry_lock
    hash_for_each_possible(rqs_registry, e, node, (unsigned long)task) {
        if (e->task == task)
            return e;
    }
    return NULL;
}


static void rqs_report(struct task_struct *p)
{
    const struct cred *cred;
    struct mm_struct *mm;
    char *pathbuf, *exe = "(none)";

    /* identity — live values, exec-safe */
    pr_warn("rqs-detect: ===== hidden task report =====\n");
    pr_warn("rqs-detect:  pid=%d tgid=%d comm=%s\n",
            task_pid_nr(p), task_tgid_nr(p), p->comm);
    pr_warn("rqs-detect:  start_time=%llu state=0x%x\n",
            p->start_time, READ_ONCE(p->__state));

    /* creds */
    rcu_read_lock();
    cred = __task_cred(p);
    pr_warn("rqs-detect:  uid=%u gid=%u euid=%u\n",
            from_kuid(&init_user_ns, cred->uid),
            from_kgid(&init_user_ns, cred->gid),
            from_kuid(&init_user_ns, cred->euid));
    rcu_read_unlock();

    /* parent */
    rcu_read_lock();
    pr_warn("rqs-detect:  ppid=%d\n", task_pid_nr(rcu_dereference(p->real_parent)));
    rcu_read_unlock();

    /* exe path — the RE-enabling field */
    mm = get_task_mm(p);          /* NULL for kthreads; takes an mm ref */
    if (mm) {
        struct file *exe_file = get_mm_exe_file(mm);   /* takes a ref, NULL-safe */
        if (exe_file) {
            pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
            if (pathbuf) {
                exe = d_path(&exe_file->f_path, pathbuf, PATH_MAX);
                if (IS_ERR(exe))
                    exe = "(unresolved)";
                pr_warn("rqs-detect:  exe=%s\n", exe);
                kfree(pathbuf);
            }
            fput(exe_file);
        }
        mmput(mm);
    } else {
        pr_warn("rqs-detect:  exe=(kernel thread, no mm)\n");
    }
    pr_warn("rqs-detect: ==============================\n");
}

static bool rqs_queue_target(struct task_struct *t, int *n) {
    // adds a target to the global targets array 
    if (*n < RQS_MAX_TARGETS) {
        get_task_struct(t); 
        targets[(*n)++] = t; 
    } else {
        pr_warn_ratelimited("rqs-kthread: cannot add target to array, size exceeded\n"); 
        return false; 
    }
    return true; 
}


static bool rqs_fifo_pop(struct rqs_notification *n)
{
    unsigned long flags;
    bool got;

    raw_spin_lock_irqsave(&rqs_fifo_lock, flags);
    got = kfifo_get(&rqs_fifo, n);
    raw_spin_unlock_irqrestore(&rqs_fifo_lock, flags);
    return got;
}


// returns next non-empty token - used in parsing reports from userland 
static char *rqs_next_token(char **cursor)
{
    char *token;
    while ((token = strsep(cursor, " \t\r")) != NULL) {
        if(*token != 0) 
            return token; 
    }
    return NULL; 
}


static void rqs_snapshot_free_rcu(struct rcu_head *head)
{
    // frees both the bitmap and the wrapper 
    struct rqs_proc_snapshot *snap = container_of(head, struct rqs_proc_snapshot, rcu); 
    bitmap_free(snap->map); 
    kfree(snap); 
}



/*
------  CROSS VIEW CHECKS SECTION ------
- checks procfs + pid hash table + tasks for a given registry entry 
*/


static bool in_proc_snapshot(pid_t pid, u64 task_start_time)
{
    // returns true by default in case of stale snapshot, returns false if pid in registry NOT in bitmap of /proc/[pid] entries reported from userland
    struct rqs_proc_snapshot *snap;
    bool found = true;

    if (pid <= 0)
        return true;
    
    rcu_read_lock();
    snap = rcu_dereference(rqs_proc_snapshot);
    if (snap && snap->map) {
        if (time_after(jiffies, snap->stamp + RQS_SNAPSHOT_TTL)) {
            found = true; // whole snapshot is too stale to trust
        } else if (task_start_time + RQS_PROC_GRACE_NS >= snap->capture_ns) {
            found = true; // task born after snapshot, can't trust presense in bitmap 
        } else if (pid > snap->max_pid) {
            found = true; // beyond this batch's largest, fail-open 
        } else {
            found = test_bit(pid, snap->map); 
        }
    }
    rcu_read_unlock(); 
    return found;
}


static bool in_pid_hash_table(struct rqs_registry_entry *e) 
{
    // returns true if pid_task can find the task (in hash table still)
    struct task_struct * t; 
    bool found = false; 
    
    rcu_read_lock();
    t = pid_task(find_vpid(task_pid_nr(e->task)), PIDTYPE_PID);
    found = (t == e->task); 
    rcu_read_unlock(); 
    return found;
}



static bool mark_in_tasks_list(void) 
{
    // enumerates the registry and marks each member with the current generation if found in tasks*
    // return false if the 
    struct task_struct * g, *t; 
    struct rqs_registry_entry *e; 
    
    unsigned long iter = 0; 

    rcu_read_lock(); 
    for_each_process_thread(g,t) {
        if (unlikely(++iter > RQS_MAX_TASKS_WALK)) {
            rcu_read_unlock();
            pr_warn_ratelimited("rqs-kthread: tasks* walk exceeded %u  - list is likely corrupted, skipping in_tasks this pass\n", RQS_MAX_TASKS_WALK); 
            return false; // fail-open 
        }
        e = rqs_registry_find(t); 
        if (e) {
            e->seen_tasks_gen = rqs_scan_gen; 
        }
    }  
    rcu_read_unlock(); 
    return true;  
}


/*
------  SCANNER THREAD SECTION ------
- the bulk of the work is in this section 
- drains the kfifo into the registry
- performs the cross view analysis 
*/


static void rqs_enforce(struct task_struct *t) 
{
    rqs_report(t); // write report to dmesg for all modes 
    switch(READ_ONCE(SCAN_MODE)) {
        case RQS_MODE_WARN:
            /* detection already logged to dmesg, nothing further to do here */ 
            break; 

        case RQS_MODE_FREEZE:
            /* mark hidden and scheduler refuses more scheduling time  */
            pr_warn_ratelimited("rqs-kthread: taking freeze enforcement action against pid=%d comm=%s...\n", task_pid_nr(t), t->comm); 
            rqs_freeze_process(t); 
            break; 

        case RQS_MODE_KILL:
            /*
             * WARNING - a process hidden with DKOM might not be safely killable using sigkill
             * as the release_task() pipeline walks lists that may be corrupted by the rootkit 
             * and may fault. Use only as a break-glass option, implemented to give the option
            */
            pr_alert("rqs-kthread: sending SIGKILL to pid=%d comm=%s...\n", task_pid_nr(t), t->comm); 
            send_sig(SIGKILL, t, 1); 
            break; 
        
        default:
            pr_warn_ratelimited("rqs-kthread: invalid SCAN_MODE: %d - defaulting to WARN\n", SCAN_MODE);
            break; 
    }
}


static bool is_kthread(struct rqs_notification *n)
{
    return n->task && (n->task->flags & PF_KTHREAD);
}


static struct rqs_registry_entry* convert_notification_to_registry_entry(struct rqs_notification *n) 
{
    struct rqs_registry_entry *e = kzalloc(sizeof(*e), GFP_KERNEL); 
    if (!e) {
        pr_err("rqs-kthread: failed to allocate memory!\n"); 
        return NULL;
    }
    e->pid = n->pid; 
    e->tgid = n->tgid;
    e->start_time = n->start_time;
    e->task = n->task;
    n->task = NULL; // registry entry now owns ref
    strscpy(e->comm, n->comm, TASK_COMM_LEN); 
    return e;
}


static void scanner_thread_epoch(void)
{
    // step 1 - empty kfifo queue into registry
    struct rqs_notification n;
    struct rqs_registry_entry *e;
    int bucket; 
    int n_targets;
    int i; 
    bool tasklist_ok; 
    int budget = 4096; // max pops per epoch 

    bool scan_kthreads = READ_ONCE(SCAN_KTHREADS); 
    
    while (budget-- > 0 && rqs_fifo_pop(&n)) {
        if (n.type == RQS_NOTIFY_NEW && !scan_kthreads && is_kthread(&n)) {
            put_task_struct(n.task);
            goto next;
        }
        switch(n.type) {
            case RQS_NOTIFY_NEW:
                e = convert_notification_to_registry_entry(&n);
                if(e) {
                    // add to the registry 
                    mutex_lock(&rqs_registry_lock); 
                    if (rqs_registry_find(e->task)) {
                        mutex_unlock(&rqs_registry_lock);
                        put_task_struct(e->task);
                        kfree(e);
                        break;
                    }
                    // registry is keyed by task_struct *
                    hash_add(rqs_registry, &e->node, (unsigned long)e->task); 
                    mutex_unlock(&rqs_registry_lock);
                } else {
                    if(n.task)
                        put_task_struct(n.task); 
                }
                break; 

            case RQS_NOTIFY_FROZEN:
                // simply log this happened 
                pr_info("rqs-kthread: received notification kernel took FREEZE enforcement action on: %d-%s\n", n.pid, n.comm); 
                break; 

            case RQS_NOTIFY_EXIT:
                // remove from registry 
                mutex_lock(&rqs_registry_lock); 
                e = rqs_registry_find(n.task);
                if (e) {
                    hash_del(&e->node);
                    put_task_struct(e->task); 
                    kfree(e); 
                } else {
                    pr_debug("rqs-kthread: received EXIT notification for KSE not in registry: pid=%d comm=%s\n", n.pid, n.comm); 
                }
                mutex_unlock(&rqs_registry_lock); 
                break; 
        }
    
    next: 
        cond_resched(); 
    }
    // step 2 - cross view scan 
    e = NULL; 
    n_targets = 0; 
    rqs_scan_gen++; 
    
    mutex_lock(&rqs_registry_lock); 
    tasklist_ok = mark_in_tasks_list(); // O(N) update to the seen_tasks_gen of each task in tasks*
    hash_for_each(rqs_registry, bucket, e, node) {
        cond_resched(); 
        bool in_hash, in_tasks, in_proc, hidden; 
        // skip exiting tasks
        if (READ_ONCE(e->task->exit_state) || (e->task->flags & PF_EXITING)) {
            e->detection_count = 0;
            continue;
        }   

        in_hash = in_pid_hash_table(e); 
        in_tasks = !tasklist_ok || (e->seen_tasks_gen == rqs_scan_gen); 
        in_proc = in_proc_snapshot(task_pid_nr(e->task), e->start_time); 
        
        // mark any task that fails any of the checks as hidden 
        hidden = !(in_hash && in_tasks && in_proc); 

        if(hidden) {
            e->detection_count++; 
            if (e->detection_count >= READ_ONCE(DETECTION_THRESHOLD) && !e->enforced) {
                pr_warn_ratelimited("rqs-kthread: DETECTION - hidden pid=%d comm=%s view=[hash:%d tasks:%d proc:%d] detect_count=%u\n", task_pid_nr(e->task), e->comm, in_hash, in_tasks, in_proc, e->detection_count); 
                if (rqs_queue_target(e->task, &n_targets))
                    e->enforced=true; // only enforce once per detection 
            }
        } else {
            e->detection_count = 0; // reset on a clean epoch 
            e->enforced = false; // re-arm 
        }
    }
    mutex_unlock(&rqs_registry_lock); 

    // step 3 - perform any enforcement actions 
    for (i = 0; i < n_targets; i++) {
        rqs_enforce(targets[i]); 
        put_task_struct(targets[i]); 
    }
}


static int scanner_thread_main(void *data)
{
    int epoch; 
    pr_info("rqs-kthread: scanning thread started...\n"); 
    while (!kthread_should_stop())
    {   
        epoch = READ_ONCE(SCANNING_EPOCH); 
        if (unlikely(epoch < 1 || epoch > 1000)) {
            // have to include this check because this value can be changed at runtime using sysfs
            pr_warn_ratelimited("rqs-kthread: invalid SCANNING_EPOCH detected, falling back to 10s\n"); 
            epoch = 10; 
        }
        scanner_thread_epoch(); 
        set_current_state(TASK_INTERRUPTIBLE);
        if (!kthread_should_stop())
            schedule_timeout(epoch * HZ);
        __set_current_state(TASK_RUNNING); 
    }
    return 0; 
}


static int init_scanner_thread(void) 
{
    int err; 
    // define the registry hash table
    hash_init(rqs_registry);
    // create and run the scanner thread 
    scanner_thread = kthread_run(scanner_thread_main, NULL, "rqs-kthread"); 
    if(IS_ERR(scanner_thread)) {
        pr_err("rqs-scanner: error creating scanner thread!\n"); 
        err = PTR_ERR(scanner_thread); 
        scanner_thread = NULL; 
        return err; 
    }
    pr_info("rqs-scanner: scanner kthread started...\n"); 

    return 0;
}


/*
------  PROC ENTRIES SECTION ------
- creates and registers function for /proc/rqs which allows userland inspection of the registry 
  and /proc/rqs_report which allows rqs-userland to report on /proc/[pid] enumeration from userland 
*/

// handle reads to /proc/rqs
static int rqs_registry_show(struct seq_file *m, void *v) 
{
    struct rqs_registry_entry *e; 
    int bucket; 

    int count = 0; 
    seq_printf(m, "----------------------- RunQueue Security Scanner Registry -----------------------\n"); 
    seq_printf(m, "%-6s\t%-6s\t%-20s\t%-16s\t%s\n",
           "pid", "tgid", "start_time", "comm", "task*");

    mutex_lock(&rqs_registry_lock); 
    hash_for_each(rqs_registry, bucket, e, node) {
         cond_resched();
        /* %px prints real kernel va — debug/research use only */
        seq_printf(m, "%-6d\t%-6d\t%-20llu\t%-16s\t0x%px\n", task_pid_nr(e->task), task_tgid_nr(e->task), e->start_time, e->comm, e->task);
        count++; 
    }
    mutex_unlock(&rqs_registry_lock); 
    seq_printf(m, "----------------------------------------------------------------------------------\n");
    seq_printf(m, "tracking KSEs: %d\n", count);
    seq_printf(m, "dropped notifications: %d%s\n",
           atomic_read(&rqs_dropped),
           atomic_read(&rqs_dropped) ? "  (WARNING: registry may be inconsistent)" : "");
    return 0; 
}


static int rqs_registry_open(struct inode *inode, struct file *file) 
{
    return single_open(file, rqs_registry_show, NULL); 
}



// handle writes to /proc/rqs_report
static int rqs_commit_snapshot(u64 gen, int max_pid, unsigned long *map)
{
    // handle committing the new snapshot if the generation is more current 
    struct rqs_proc_snapshot *snap, *old;

    snap = kzalloc(sizeof(*snap), GFP_KERNEL); 
    if(!snap) 
        return -ENOMEM;
    snap->generation = gen;
    snap->max_pid = max_pid;
    snap->map = map;
    snap->stamp = jiffies; 
    snap->capture_ns = ktime_get_ns(); 

    spin_lock(&rqs_proc_snapshot_lock);
    if (gen <= rqs_report_gen) {
        spin_unlock(&rqs_proc_snapshot_lock);
        kfree(snap);
        return -ESTALE;
    }
    rqs_report_gen = gen;
    old = rcu_dereference_protected(rqs_proc_snapshot, lockdep_is_held(&rqs_proc_snapshot_lock));
    rcu_assign_pointer(rqs_proc_snapshot, snap);
    spin_unlock(&rqs_proc_snapshot_lock);

    if(old)
        call_rcu(&old->rcu, rqs_snapshot_free_rcu); 

    return 0; 
} 


static int rqs_ingest_report(char *buf, size_t len)
{
    // EXPECTS FORMAT: "GEN [uint64] MAX [int] COUNT [int] [pid] [pid]"
    // returns 0 on commit, -EINVAL for malformed, -ESTALE for old generation, or -ENOMEM
    char *cursor = buf; 
    char *token; 
    u64 gen;
    int max_pid, count, pid, n, ret;
    unsigned long *map; 

    if (len < 19) {
        return -EINVAL; // can't be long enough to match the format 
    } 
    n = 0; 
    buf[len] = '\0'; // null terminate the incoming buffer 
    // parse the header 
    token = rqs_next_token(&cursor); 
    if(!token || strcmp(token, "GEN"))
        return -EINVAL;
    token = rqs_next_token(&cursor); 
    if(!token || kstrtou64(token, 10, &gen))
        return -EINVAL;
    token = rqs_next_token(&cursor);
    if(!token || strcmp(token, "MAX"))
        return -EINVAL;
    token = rqs_next_token(&cursor);
    if (!token || kstrtoint(token, 10, &max_pid))
        return -EINVAL;
    if (max_pid <= 0 || max_pid > PID_MAX_LIMIT)
        return -EINVAL;
    token = rqs_next_token(&cursor);
    if (!token || strcmp(token, "COUNT"))
        return -EINVAL;
    token = rqs_next_token(&cursor);
    if (!token || kstrtoint(token, 10, &count))
        return -EINVAL;
    if (count <= 0 || count > max_pid)
        return -EINVAL;

    // header validated, allocated bitmap 
    map = bitmap_zalloc(max_pid+1, GFP_KERNEL); 
    if(!map)
        return -ENOMEM;
    
    // populate with entries 
    while ((token = rqs_next_token(&cursor)) != NULL) {
        if (n >= count) {
            bitmap_free(map); 
            return -EINVAL; // more entries than COUNT said there would be
        }
        if (kstrtoint(token, 10, &pid)) {
            bitmap_free(map);
            return -EINVAL;
        }
        if (pid <= 0 || pid > max_pid) {
            bitmap_free(map);
            return -EINVAL; // larger max than promised, would overflow
        }
        set_bit(pid, map);
        n++; 
    }
    if (n != count) {
        bitmap_free(map);
        return -EINVAL; // fewer entries than COUNT promised 
    }
    ret = rqs_commit_snapshot(gen, max_pid, map); 
    if (ret < 0) {
        bitmap_free(map);
        return ret;
    }
    return 0; 
}




static ssize_t rqs_report_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    struct rqs_report_ctx *ctx = file->private_data;
    size_t newlen;
    char *nl;
    if(count == 0)
        return 0; 
    
    if (ctx->len + count > RQS_REPORT_MAX_BYTES) {
        ctx->len = 0; 
        return -EFBIG; // don't let the input from userland grow unbounded 
    }

    // allocate more space if needed 
    newlen = ctx->len + count;
    if (newlen > ctx->cap) {
        char *nb = krealloc(ctx->buf, newlen, GFP_KERNEL); 
        if (!nb)
            return -ENOMEM;
        ctx->buf = nb;
        ctx->cap = newlen; 
    }
    
    if(copy_from_user(ctx->buf + ctx->len, ubuf, count))
        return -EFAULT; 
    ctx->len += count;
    nl = memchr(ctx->buf, '\n', ctx->len);
    if(nl) {
        // newline - ingested whole new report 
        size_t frame_len = nl - ctx->buf;
        int ret = rqs_ingest_report(ctx->buf, frame_len); 

        ctx->len = 0; 
        if(ret < 0)
            return ret; 
    }
    *ppos += count; 
    return count; 

}

static int rqs_report_open(struct inode *inode, struct file  *file) 
{
    struct rqs_report_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL); 
    if (!ctx) 
        return -ENOMEM; 
    file->private_data = ctx; 
    return 0; 
}

static int rqs_report_release(struct inode *inode, struct file *file) 
{
    struct rqs_report_ctx *ctx = file->private_data; 
    if(ctx) {
        kfree(ctx->buf); 
        kfree(ctx); 
    }
    return 0; 
}

// define the ops for read /proc/rqs
static const struct proc_ops proc_file_ops_registry = {
    .proc_open = rqs_registry_open,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_read = seq_read, 
}; 

// define the ops for read /proc/rqs_report
static const struct proc_ops proc_file_ops_reporting = {
    .proc_open = rqs_report_open, 
    .proc_write = rqs_report_write, 
    .proc_release = rqs_report_release,
    .proc_lseek = noop_llseek,
}; 


static int create_proc_fs_entries(void) 
{
    proc_entry_registry = proc_create(PROC_ENTRY, 0444, NULL, &proc_file_ops_registry); 
    if (!proc_entry_registry) {
        return -ENOMEM; 
    }
    pr_info("rqs-scanner: created /proc/%s\n", PROC_ENTRY); 

    proc_entry_reporting = proc_create(PROC_ENTRY_REPORTING, 0200, NULL, &proc_file_ops_reporting); 
    if (!proc_entry_reporting) {
        proc_remove(proc_entry_registry); 
        return -ENOMEM; 
    }
    pr_info("rqs-scanner: created /proc/%s\n", PROC_ENTRY_REPORTING); 

    return 0; 
}


/*
------  MODULE INIT AND EXIT SECTION ------
- called when module inserted and removed  
*/

static void cleanup_registry(void) 
{
    struct rqs_registry_entry *e; 
    struct hlist_node *tmp;
    int bucket; 
    mutex_lock(&rqs_registry_lock); 
    hash_for_each_safe(rqs_registry, bucket, tmp, e, node) {
        hash_del(&e->node);
        put_task_struct(e->task); 
        kfree(e); 
        
    }
    mutex_unlock(&rqs_registry_lock); 
}

static void cleanup_proc_snapshot(void)
{
    struct rqs_proc_snapshot *snap = rcu_dereference_protected(rqs_proc_snapshot, 1); 
    RCU_INIT_POINTER(rqs_proc_snapshot, NULL); 
    if(snap) {
        synchronize_rcu();
        bitmap_free(snap->map);
        kfree(snap);
    }
}


static int __init scanner_init(void) 
{
    int res;
    scanner_thread = NULL; 
    res = init_scanner_thread(); 
    if (res != 0 ) {
        pr_err("rqs-scanner: failed to init scanner thread. exiting...\n"); 
        return res; 
    } 
    res = create_proc_fs_entries(); 
    if (res != 0 ) {
        pr_err("rqs_scanner: failed to created procfs entries. exiting...\n"); 
        kthread_stop(scanner_thread); 
        return res; 
    }
    res = rqs_register_callback(rqs_scanner_callback); 
    if (res) {
        pr_err("rqs-scanner: callback registration failed (%d)\n", res); 
        proc_remove(proc_entry_registry);
        proc_remove(proc_entry_reporting);  
        kthread_stop(scanner_thread); 
        return res; 
    }
    pr_info("rqs-scanner: loaded, callback registered\n"); 
    return 0; 
}

static void __exit scanner_exit(void) 
{
    struct rqs_notification n; 
    rqs_unregister_callback(rqs_scanner_callback); 
    synchronize_rcu(); 
    if(scanner_thread) {
        kthread_stop(scanner_thread); 
    } 
    pr_info("rqs-scanner: killed kthread...\n"); 
    if (proc_entry_registry) {
        proc_remove(proc_entry_registry); 
    }
    if (proc_entry_reporting) {
        proc_remove(proc_entry_reporting); 
    }
    pr_info("rqs-scanner: removed procfs entries...\n");
    while(rqs_fifo_pop(&n)) {
        if (n.type ==RQS_NOTIFY_NEW && n.task) {
            put_task_struct(n.task); 
        }
    } 
    pr_info("rqs-scanner: notification queue cleared...\n");
    cleanup_proc_snapshot();
    rcu_barrier();
    pr_info("rqs-scanner: bitmap of /proc/[pid] entries cleared...\n");
    cleanup_registry(); 
    pr_info("rqs-scanner: removed registry..\n");
    pr_info("rqs-scanner: module unloaded\n"); 
}

module_init(scanner_init); 
module_exit(scanner_exit); 