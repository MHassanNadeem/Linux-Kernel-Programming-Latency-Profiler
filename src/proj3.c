/* Linux Kernel Programming
* Project 3
* 
* Hassan Nadeem
* hnadeem@vt.edu
* */

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/stacktrace.h>
#include <linux/seq_file.h>
#include <linux/jhash.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/types.h>


/*---------------------------------------------------------------------------*/
/* Macros */
/*---------------------------------------------------------------------------*/
#define DBG(var, type)          printk(KERN_INFO #var" = %"#type"\n", var)
#define DBGM(var, type, desc)   printk(KERN_INFO desc" = %"#type"\n", var)
#define PRINT(msg, ...)         printk(KERN_INFO msg, ##__VA_ARGS__)
#define ERROR(msg, ...)         printk(KERN_ALERT "ERROR: "msg, ##__VA_ARGS__)

#define STACK_STR_LEN 1024
#define STACK_LEN     16

/*---------------------------------------------------------------------------*/
/* Global Variables */
/*---------------------------------------------------------------------------*/
LIST_HEAD(queue);
DEFINE_HASHTABLE(int_hashtable, 14); /* 2^14 buckets */
struct rb_root rbRoot = RB_ROOT;

static DEFINE_SPINLOCK(queue_lock);
static DEFINE_SPINLOCK(ht_lock);

/*---------------------------------------------------------------------------*/
/* Data Structures */
/*---------------------------------------------------------------------------*/
typedef enum {START_SLEEP, STOP_SLEEP} SchedEvent;

struct processID{
    /* START OF KEY */
    pid_t pid; // Needs to be at the top
    unsigned long stack_entries[STACK_LEN]; // Needs to be 2nd
    /* END OF KEY */
    struct stack_trace trace;
    char comm[TASK_COMM_LEN];
    unsigned long stack_entries_user[STACK_LEN];
    struct stack_trace trace_user;
};

struct myData{
    struct processID id;
    unsigned long long sleepTime;
    unsigned long long dequeueTime;
    unsigned long long timeStamp;
    SchedEvent event;
};

struct int_hashtableEntry{
    struct rb_node     rbnode;
    struct hlist_node  hnode;
    struct myData      *data;
    bool               isInTree;
};

/*---------------------------------------------------------------------------*/
/* Synchronized Queue Implementation */
/*---------------------------------------------------------------------------*/
struct MyPointerList{
    void* data;
    struct list_head list;
};

static inline int enqueue(struct list_head *head, void *data){
    struct MyPointerList *tmp;
    unsigned long flags;

    tmp = (struct MyPointerList*)kmalloc(sizeof(struct MyPointerList), GFP_ATOMIC);
    if(tmp == NULL) goto error;
    tmp->data = data;
    
    spin_lock_irqsave(&queue_lock, flags);
        list_add(&tmp->list, head);
    spin_unlock_irqrestore(&queue_lock, flags);
    
    return 0;
    
    error:
        ERROR("kmalloc in enqueue failed");
        return -ENOMEM;
}

static inline int queue_isEmpty(struct list_head *head){
    int isEmpty;
    unsigned long flags;
    
    spin_lock_irqsave(&queue_lock, flags);
        isEmpty = list_empty(head);
    spin_unlock_irqrestore(&queue_lock, flags);
       
    return isEmpty;
}

static void* dequeue(struct list_head *head){
    struct MyPointerList *listNode;
    void *data;
    unsigned long flags;
        
    spin_lock_irqsave(&queue_lock, flags);
        if(list_empty(head)){
            ERROR("trying to dequeue an empty queue");
            return NULL;
        }
        listNode = list_last_entry(head, struct MyPointerList, list);
        list_del(&listNode->list);
    spin_unlock_irqrestore(&queue_lock, flags);
        
    data = listNode->data;
    kfree(listNode);
    return data;
}

static int queue_destroy(struct list_head *head){
    unsigned long flags;
    struct MyPointerList *tmp;
    struct list_head *pos, *pos2;
    
    spin_lock_irqsave(&queue_lock, flags);
        list_for_each_safe(pos, pos2, head){
            tmp = list_entry(pos, struct MyPointerList, list);
            list_del(pos);
            kfree(tmp->data);
            kfree(tmp);
        }
    spin_unlock_irqrestore(&queue_lock, flags);
    
    return 0;
}
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Userspace stacktrace - based on kernel/trace/trace_sysprof.c */
/*---------------------------------------------------------------------------*/
struct stack_frame_user {
    const void __user    *next_fp;
    unsigned long        ret_addr;
};

static int
copy_stack_frame(const void __user *fp, struct stack_frame_user *frame)
{
    int ret;

    if (!access_ok(VERIFY_READ, fp, sizeof(*frame)))
        return 0;

    ret = 1;
    pagefault_disable();
    if (__copy_from_user_inatomic(frame, fp, sizeof(*frame)))
        ret = 0;
    pagefault_enable();

    return ret;
}

static inline void __save_stack_trace_user(struct stack_trace *trace)
{
    const struct pt_regs *regs = task_pt_regs(current);
    const void __user *fp = (const void __user *)regs->bp;

    if (trace->nr_entries < trace->max_entries)
        trace->entries[trace->nr_entries++] = regs->ip;

    while (trace->nr_entries < trace->max_entries) {
        struct stack_frame_user frame;

        frame.next_fp = NULL;
        frame.ret_addr = 0;
        if (!copy_stack_frame(fp, &frame))
            break;
        if ((unsigned long)fp < regs->sp)
            break;
        if (frame.ret_addr) {
            trace->entries[trace->nr_entries++] =
                frame.ret_addr;
        }
        if (fp == frame.next_fp)
            break;
        fp = frame.next_fp;
    }
}

void save_stack_trace_user(struct stack_trace *trace)
{
    /*
     * Trace user stack if we are not a kernel thread
     */
    if (current->mm) {
        __save_stack_trace_user(trace);
    }
}

/*---------------------------------------------------------------------------*/

struct myData *newMyData(void){
    struct myData *data = (struct myData *) kmalloc(sizeof(struct myData), GFP_ATOMIC);
    if(data == NULL){
        ERROR("kmalloc in newMyData failed");
        return NULL;
    }
    
    /* Fill any struct padding with zeros for consistent hashing */
    memset(
        (char*)&data->id.pid + sizeof(data->id.pid), // Start of padding
        0,
        (char*)&data->id.stack_entries - (char*)&data->id.pid - sizeof(data->id.pid) // Size of padding
    );
    
    /* init kernel trace */
    data->id.trace.nr_entries = 0;
    data->id.trace.entries = data->id.stack_entries;
    data->id.trace.max_entries = STACK_LEN;
    data->id.trace.skip = 0;
    
    /* init user trace */
    data->id.trace_user.nr_entries = 0;
    data->id.trace_user.entries = data->id.stack_entries_user;
    data->id.trace_user.max_entries = STACK_LEN;
    data->id.trace_user.skip = 0;
    data->id.stack_entries_user[data->id.trace_user.nr_entries++] = ULONG_MAX;
    
    return data;
}

void freeMyData(struct myData *data){
    kfree(data);
}

void printStack(struct myData *data){
    char buffer[STACK_STR_LEN];
    
    snprint_stack_trace(buffer, STACK_STR_LEN, &data->id.trace, 1);
    
    PRINT("PID: %ul %s", data->id.pid, data->id.comm);
    PRINT("%s", buffer);
}

static int hashtable_destroy(struct hlist_head *hashtable_head){
    int i;
    struct int_hashtableEntry *tmp;
    struct hlist_node *tmp_hlist_node;
    
    hash_for_each_safe(int_hashtable, i, tmp_hlist_node, tmp, hnode){
        hash_del(&tmp->hnode);
        kfree(tmp->data);
        kfree(tmp);
    }
    
    return 0;
}

static inline u32 getHash(struct myData *data){
    char *start = (char *)&data->id;
    char *end   = (char *)(&data->id.stack_entries[data->id.trace.nr_entries]);
    
    return jhash(start, end-start, 0);
}

static inline bool myDataisEqual(struct myData *data1, struct myData *data2){
    char *start = (char *)&data1->id;
    char *end   = (char *)(&data1->id.stack_entries[data1->id.trace.nr_entries]);
    
    return data1->id.trace.nr_entries == data2->id.trace.nr_entries && memcmp(data1, data2, end-start) == 0;
}

struct int_hashtableEntry *hashtable_search(struct myData *data){
    struct int_hashtableEntry *ret;
    
    hash_for_each_possible(int_hashtable, ret, hnode, getHash(data)){
        if(myDataisEqual(data, ret->data))
            return ret;
    }

    return NULL;
}

int rbtree_insert(struct rb_root *root, struct int_hashtableEntry *data){
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    /* Figure out where to put new rbnode */
    while (*new){
        struct int_hashtableEntry *this = container_of(*new, struct int_hashtableEntry, rbnode);

        parent = *new;
        if (data->data->sleepTime < this->data->sleepTime)
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }

    /* Add new rbnode and rebalance tree. */
    rb_link_node(&data->rbnode, parent, new);
    rb_insert_color(&data->rbnode, root);

    return 0;
}

void updateStackTrace(struct task_struct *task, struct myData *data){
    if(task == current){
        data->id.trace.skip = 5;
    }else{
        data->id.trace.skip = 0;
    }
    save_stack_trace_tsk(task, &(data->id.trace));
}

// dequeue/deactivate
static inline int task_start_sleep(struct task_struct *task, unsigned long long time){
    struct myData *tmpData = newMyData();
    tmpData->id.pid = task->pid;
    strcpy(tmpData->id.comm, task->comm);
    updateStackTrace(task, tmpData);
    tmpData->timeStamp = time;
    tmpData->event = START_SLEEP;
    
    save_stack_trace_user(&(tmpData->id.trace_user));
    
    enqueue(&queue, tmpData);
    
    return 0;
}

// enqueue/Activate
static inline int task_stop_sleep(struct task_struct *task, unsigned long long time){
    struct myData *tmpData = newMyData();
    tmpData->id.pid = task->pid;
    strcpy(tmpData->id.comm, task->comm);
    updateStackTrace(task, tmpData);
    tmpData->timeStamp = time;
    tmpData->event = STOP_SLEEP;
    
    enqueue(&queue, tmpData);
    
    return 0;
}

#define ARG_REG_1 di
#define ARG_REG_2 si
#define ARG_REG_3 dx
#define ARG_REG_4 cx

/* kprobe pre_handler: called just before the probed instruction is executed */
static int activate_task_handler_pre(struct kprobe *p, struct pt_regs *regs){
    struct task_struct *task_pointer = (struct task_struct *)regs->ARG_REG_2;
    task_stop_sleep(task_pointer, rdtsc());
    
    return 0;
}

static int deactivate_task_handler_pre(struct kprobe *p, struct pt_regs *regs){
    struct task_struct *task_pointer = (struct task_struct *)regs->ARG_REG_2;
    task_start_sleep(task_pointer, rdtsc());
    
    return 0;
}

static void rbTreePrinter(struct rb_root* root, struct seq_file *m){
    struct myData *data;
    struct rb_node *cursor = rb_last(root);
    char *buffer = (char *) kmalloc(sizeof(char) * STACK_STR_LEN, GFP_ATOMIC);
    if(buffer == NULL){
        ERROR("kmalloc in rbTreePrinter failed");
        return;
    }
    
    while(cursor){
        data = rb_entry(cursor, struct int_hashtableEntry, rbnode)->data;
        seq_printf(m, "-- %d - %s\n", data->id.pid, data->id.comm );
        seq_printf(m, "Sleep Time: %llu\n", data->sleepTime);
        snprint_stack_trace(buffer, STACK_STR_LEN, &data->id.trace, 1);
        seq_printf(m, "Kernel Stack:\n%s\n", buffer);
        if(data->id.trace_user.nr_entries > 1){
            snprint_stack_trace(buffer, STACK_STR_LEN, &data->id.trace_user, 1);
            seq_printf(m, "User Stack:\n%s\n", buffer);
        }
        
        cursor = rb_prev(cursor);
    };
    
    kfree(buffer);
}

/*********************************************************/
/* PROC */
/*********************************************************/
#define PROCFS_NAME         "lattop"

static int lattop_proc_show(struct seq_file *m, void *v){
    seq_printf(m, "++++++++++++++++++++\n");

    spin_lock(&ht_lock);
        rbTreePrinter(&rbRoot, m);
    spin_unlock(&ht_lock);
    
    seq_printf(m, "--------------------\n");
    
    return 0;
}

static int lattop_proc_open(struct inode *inode, struct file *file){
    return single_open(file, lattop_proc_show, NULL);
}

static const struct file_operations sysemu_proc_fops = {
    .owner    = THIS_MODULE,
    .open     = lattop_proc_open,
    .read     = seq_read,
    .llseek   = seq_lseek,
    .release  = single_release,
};

void process_start_sleep(struct myData *data){
    struct int_hashtableEntry *htEntry;
    // PRINT("START");
    // printStack(data);
    
    htEntry = hashtable_search(data);
    if(htEntry == NULL){
        htEntry = (struct int_hashtableEntry *) kmalloc(sizeof(struct int_hashtableEntry), GFP_ATOMIC);
        if(htEntry == NULL){
            ERROR("kmalloc in process_start_sleep failed");
            return;
        }
        htEntry->data = data;
        htEntry->data->dequeueTime = htEntry->data->timeStamp;
        htEntry->isInTree = false;
        hash_add(int_hashtable, &htEntry->hnode, getHash(htEntry->data));
    }else{
        htEntry->data->dequeueTime = data->timeStamp;
        freeMyData(data);
    }
}

void process_end_sleep(struct myData *data){
    struct int_hashtableEntry *htEntry;
    // PRINT("END");
    // printStack(data);
    
    htEntry = hashtable_search(data);
    if(htEntry == NULL){
        freeMyData(data);
        return;
    }
    
    htEntry->data->sleepTime += (data->timeStamp - htEntry->data->dequeueTime);
    
     if(htEntry->isInTree){
        rb_erase(&htEntry->rbnode, &rbRoot);
    }
    
    rbtree_insert(&rbRoot, htEntry);
    htEntry->isInTree = true;
    
    freeMyData(data);
}

static struct task_struct *kthread = NULL;
int work_func(void *args){
    struct myData *data;
    PRINT("Worker thread started!");
    while(!kthread_should_stop()){
        msleep(50);
        
        spin_lock(&ht_lock);
            while(!queue_isEmpty(&queue)){
                data = (struct myData *) dequeue(&queue);
                if(data->event == START_SLEEP){
                    process_start_sleep(data);
                }else{
                    process_end_sleep(data);
                }
            }
        spin_unlock(&ht_lock);
    }
    
    do_exit(0);
}


/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp_activate_task = {
    .symbol_name    = "activate_task",
};

static struct kprobe kp_deactivate_task = {
    .symbol_name    = "deactivate_task"
};

static int __init lattop_module_init(void){
    int ret = 0;

    /* Register kprobe */
    kp_activate_task.pre_handler = activate_task_handler_pre;
    kp_deactivate_task.pre_handler = deactivate_task_handler_pre;
    
    ret += register_kprobe(&kp_activate_task);
    ret += register_kprobe(&kp_deactivate_task);
    
    if (ret < 0) {
        ERROR("register_kprobe failed");
        return -1;
    }
    /*---------------------------------------*/
    
    /* Start worker kthread */
    kthread = kthread_run(work_func, NULL, "lattop_worker");
    if(kthread == ERR_PTR(-ENOMEM)){
        ERROR("Could not run kthread");
        return -1;
    }
    /*---------------------------------------*/
    
    /* Create the /proc file */
    if(!proc_create(PROCFS_NAME, 0, NULL, &sysemu_proc_fops)) {
        ERROR("Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }
    /*---------------------------------------*/
    
    return 0;
}

static void __exit lattop_module_exit(void){
    unregister_kprobe(&kp_activate_task);
    unregister_kprobe(&kp_deactivate_task);
    remove_proc_entry(PROCFS_NAME, NULL);
    if(kthread) kthread_stop(kthread);
    
    /* Free memory */
    hashtable_destroy(int_hashtable); // frees hashtable & rbtree
    queue_destroy(&queue);
}

module_init(lattop_module_init)
module_exit(lattop_module_exit)
MODULE_LICENSE("GPL");
