#include <linux/rqs.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rcupdate.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/jump_label.h>
#include <linux/errno.h>


static rqs_callback_t __rcu rqs_scanner_callback = NULL; 
static DEFINE_MUTEX(rqs_callback_lock);
DEFINE_STATIC_KEY_FALSE(rqs_enabled);  

int rqs_register_callback(rqs_callback_t cb) {
    int ret = 0; 
    mutex_lock(&rqs_callback_lock); 
    if (rcu_access_pointer(rqs_scanner_callback)) {
        ret = -EBUSY;
    } else {
        rcu_assign_pointer(rqs_scanner_callback, cb);
        static_branch_enable(&rqs_enabled); 
    }   
    mutex_unlock(&rqs_callback_lock); 
    if (!ret)
        pr_info("rqs-core: scanner registered\n");
    return ret;  
}
EXPORT_SYMBOL_GPL(rqs_register_callback); 

void rqs_unregister_callback(rqs_callback_t cb) {
    bool matched = false; 

    mutex_lock(&rqs_callback_lock); 
    if (rcu_access_pointer(rqs_scanner_callback) == cb) {
        static_branch_disable(&rqs_enabled); 
        RCU_INIT_POINTER(rqs_scanner_callback, NULL); 
        matched = true; 
    }
    mutex_unlock(&rqs_callback_lock); 

    if(!matched) {
        pr_warn("rqs-core: rejected unregister because different from registered function.\n"); 
        return; 
    }

    synchronize_rcu(); 
    pr_info("rqs-core: scanner unregistered\n"); 
}
EXPORT_SYMBOL_GPL(rqs_unregister_callback); 


bool __rqs_notify_scanner(struct task_struct *p, int type) {

    rqs_callback_t cb; 
    bool delivered = false; 
    
    rcu_read_lock(); 
    cb = rcu_dereference(rqs_scanner_callback);  

    // does nothing if no callback function registered 
    if (cb) {
        struct rqs_notification n = {
            .pid = p->pid, 
            .tgid = p->tgid, 
            .start_time = p->start_time, 
            .task = p,
            .type = type,
        }; 
        strscpy(n.comm, p->comm, sizeof(n.comm)); 
        cb(&n); 
        delivered = true; 
    }
    rcu_read_unlock(); 
    return delivered; 
}

static int __init rqs_init(void) {
    pr_info("rqs-core: RunQueue Security initialized\n"); 
    pr_info("rqs-core: waiting for scanner callback registration...\n");
    return 0; 
}

early_initcall(rqs_init); 