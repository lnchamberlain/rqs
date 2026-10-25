/* ------ RQS ------
* Shared definitions for enums 
* and structs between kernel and 
* scanner LKM
*/
#ifndef _LINUX_RQS_H
#define _LINUX_RQS_H

#include <linux/types.h>
#include <linux/sched.h> 
#include <linux/jump_label.h>

DECLARE_STATIC_KEY_FALSE(rqs_enabled);


#define RQS_NOTIFY_NEW  0 // newly runnable task for scanner to track
#define RQS_NOTIFY_EXIT 1 // task being reaped, remove from registry
#define RQS_NOTIFY_FROZEN   2 // task dequeued as enforcement action

// optimization to avoid threads getting an rcu lock when no callback function is registered s
bool __rqs_notify_scanner(struct task_struct *p, int type);

static inline bool rqs_notify_scanner(struct task_struct *p, int type)
{
    if (static_branch_unlikely(&rqs_enabled))
        return __rqs_notify_scanner(p, type);
    return false; 
}


// notification fields
struct rqs_notification {
    pid_t pid;
    pid_t tgid; 
    u64 start_time; 
    char comm[TASK_COMM_LEN]; 
    struct task_struct * task; 
    int type; 
}; 

typedef void (*rqs_callback_t)(struct rqs_notification *n); 

// interface 
int rqs_register_callback(rqs_callback_t cb); 
void rqs_unregister_callback(rqs_callback_t cb); 
void rqs_freeze_task(struct task_struct *p); 
void rqs_freeze_process(struct task_struct *p); 



#endif /* _LINUX_RQS_H */