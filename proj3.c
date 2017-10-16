/* Linux Kernel Programming
* Project 3
* 
* Hassan Nadeem
* hnadeem@vt.edu
* */

#include <linux/kernel.h>
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


#define DBG(var, type)          printk(KERN_INFO #var" = %"#type"\n", var)
#define DBGM(var, type, desc)   printk(KERN_INFO desc" = %"#type"\n", var)
#define PRINT(msg, ...)         printk(KERN_INFO msg, ##__VA_ARGS__)

// Concurrent access

/* Data Structures */
#define STACK_STR_LEN 1024
#define STACK_LEN     16

struct processID{
    pid_t pid; // Needs to be at the top
    unsigned long stack_entries[STACK_LEN];
};

struct myData{
    struct processID id;
    struct stack_trace trace;
    char comm[TASK_COMM_LEN];
    unsigned long long sleepTime;
    unsigned long long dequeueTime;
};

void printStack(struct myData *data){
    char buffer[STACK_STR_LEN];
    
    snprint_stack_trace(buffer, STACK_STR_LEN, &data->trace, 1);
}

struct myData *newMyData(void){
    struct myData *data = (struct myData *) kmalloc(sizeof(struct myData), GFP_ATOMIC);
    
    /* Fill any struct padding with zeros for consistent hashing */
    memset(
        (char*)&data->id.pid + sizeof(data->id.pid), // Start of padding
        0,
        (char*)&data->id.stack_entries - (char*)&data->id.pid - sizeof(data->id.pid) // Size of padding
    );
    
    /* init trace */
    data->trace.nr_entries = 0;
    data->trace.entries = data->id.stack_entries;
    data->trace.max_entries = STACK_LEN;
    data->trace.skip = 0;
    
    return data;
}

void freeMyData(struct myData *data){
    kfree(data);
}

DEFINE_HASHTABLE(int_hashtable, 14); /* 2^14 buckets */ // FIX ME

struct int_hashtableEntry{
    struct hlist_node hnode;
    struct myData *data;
};

static inline u32 getHash(struct myData *data){
    char *start = (char *)&data->id;
    char *end   = (char *)(&data->id.stack_entries[data->trace.nr_entries]);
    
    return jhash(start, end-start, 0);
}

static inline bool myDataisEqual(struct myData *data1, struct myData *data2){
    char *start = (char *)&data1->id;
    char *end   = (char *)(&data1->id.stack_entries[data1->trace.nr_entries]);
    
    return data1->trace.nr_entries == data2->trace.nr_entries && memcmp(data1, data2, end-start) == 0;
}

struct int_hashtableEntry *hashtable_search(struct myData *data){
    struct int_hashtableEntry *ret;
    
    hash_for_each_possible(int_hashtable, ret, hnode, getHash(data)){
        if(myDataisEqual(data, ret->data))
            return ret;
    }

    return NULL;
}

struct int_rbnode{
    struct rb_node node;
    struct myData *data;
};

struct rb_root rbRoot = RB_ROOT;

int rbtree_insert(struct rb_root *root, struct int_rbnode *data){
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    /* Figure out where to put new node */
    while (*new){
        struct int_rbnode *this = container_of(*new, struct int_rbnode, node);

        parent = *new;
        if (data->data->sleepTime < this->data->sleepTime)
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);

    return 0;
}

void updateStackTrace(struct task_struct *task, struct myData *data){
    if(task == current){
        data->trace.skip = 5;
    }else{
        data->trace.skip = 0;
    }
    save_stack_trace_tsk(task, &(data->trace));
}

/* Will either return existing myData struct if found, else return a new struct */
static inline bool getAppropriateStruct(struct int_hashtableEntry **htEntry, struct task_struct *task){
    struct myData *tmpData = newMyData();
    
    tmpData->id.pid = task->pid;
    updateStackTrace(task, tmpData);
    
    *htEntry = hashtable_search(tmpData);
    if(*htEntry == NULL){
        // strcpy(tmpData->comm, task->comm); printStack(tmpData); // Debug
        strcpy(tmpData->comm, task->comm);
        *htEntry = (struct int_hashtableEntry *) kmalloc(sizeof(struct int_hashtableEntry), GFP_ATOMIC);
        (*htEntry)->data = tmpData;
        return false;
    }else{
        kfree(tmpData);
        return true;
    }
}


// dequeue/deactivate
static inline int task_start_sleep(struct task_struct *task){
    struct int_hashtableEntry *htEntry;
    struct int_rbnode *rbNode;
    
    if(getAppropriateStruct(&htEntry, task) == false){
        /* New struct, need to add it to rbtree and hashtable */
        /* Add to rbtree */
        rbNode = (struct int_rbnode*) kmalloc(sizeof(struct int_rbnode), GFP_ATOMIC);
        rbNode->data = htEntry->data;
        rbtree_insert(&rbRoot, rbNode);
        
        // /* Add to hashtable */
        hash_add(int_hashtable, &htEntry->hnode, getHash(htEntry->data));
        // PRINT("--------------------------------------------------------------Added");
    }else{
        
    }
    
    htEntry->data->dequeueTime = rdtsc();
    // DBG(htEntry->data->sleepTime, llu);
    
    // PRINT("DEACK"); printStack( htEntry->data);
    
    return 0;
}

// enqueue/Activate
static inline int task_stop_sleep(struct task_struct *task){
    struct int_hashtableEntry *htEntry;
    // PRINT("THIS FUNCTION IS NOT BEING CALLED. I DON'T KNOW WHY");
    /* If the struct was not already there */
    if(getAppropriateStruct(&htEntry, task) == false){
        // PRINT("ACK"); printStack( htEntry->data);
        
        freeMyData(htEntry->data);
        kfree(htEntry);
        return 0;
    }
    
    // PRINT("ACK"); printStack( htEntry->data);
    
    htEntry->data->sleepTime += (rdtsc() - htEntry->data->dequeueTime);
    DBG(htEntry->data->sleepTime, llu);
    // PRINT("THIS FUNCTION IS NOT BEING CALLED. I DON'T KNOW WHY");
    
    return 0;
}

#define ARG_REG_1 di
#define ARG_REG_2 si
#define ARG_REG_3 dx
#define ARG_REG_4 cx

/* kprobe pre_handler: called just before the probed instruction is executed */
static int activate_task_handler_pre(struct kprobe *p, struct pt_regs *regs){
    struct task_struct *task_pointer = (struct task_struct *)regs->ARG_REG_2;
    // PRINT("+ %04d=%s", task_pointer->pid, task_pointer->comm);
    
    // pr_info("<%s> pre_handler: p->addr = 0x%p, ip = %lx, flags = 0x%lx\n", p->symbol_name, p->addr, regs->ip, regs->flags);

    // dump_stack_print_info(KERN_DEFAULT);
    
    	// printk("%sCPU: %d PID: %d Comm: %.20s\n", KERN_DEFAULT, raw_smp_processor_id(), current->pid, current->comm);
    // dump_stack();
    // pr_info("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
    /* A dump_stack() here will give a stack backtrace */
    task_stop_sleep(task_pointer);
    
    return 0;
}

static int deactivate_task_handler_pre(struct kprobe *p, struct pt_regs *regs){
    struct task_struct *task_pointer = (struct task_struct *)regs->ARG_REG_2;
    
    // PRINT("- %04d=%s", task_pointer->pid, task_pointer->comm);
    
    task_start_sleep(task_pointer);
    
    return 0;
}

// static struct task_struct *kthread;

// char cbuffer[1024];

#define HOW_MANY_ENTRIES_TO_STORE 16

unsigned long stack_entries[HOW_MANY_ENTRIES_TO_STORE];
struct stack_trace trace = {
    .nr_entries = 0,
    .entries = &stack_entries[0],

    .max_entries = HOW_MANY_ENTRIES_TO_STORE,

    /* How many "lower entries" to skip. */
    .skip = 1
};

/*********************************************************/
/* PROC */
/*********************************************************/
#define PROCFS_NAME 		"lattop"

static int lattop_proc_show(struct seq_file *m, void *v){
    char *buffer = (char *) kmalloc(sizeof(char) * STACK_STR_LEN, GFP_ATOMIC);
    int i;
    struct int_hashtableEntry *tmp;
    struct hlist_node *tmp_hlist_node;
    
    seq_printf(m, "START\n");
    
    hash_for_each_safe(int_hashtable, i, tmp_hlist_node, tmp, hnode){
        seq_printf(m, "-- %d - %s\n", tmp->data->id.pid, tmp->data->comm );
        seq_printf(m, "Sleep Time: %llu\n", tmp->data->sleepTime);
        snprint_stack_trace(buffer, STACK_STR_LEN, &tmp->data->trace, 1);
        seq_printf(m, "%s\n", buffer);
    }
    
    seq_printf(m, "STOP\n");
    
    kfree(buffer);
    
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


/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp_activate_task = {
    .symbol_name	= "activate_task",
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
        PRINT("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    /*---------------------------------------*/
    
    // kthread = kthread_create(work_func, NULL, "mykthread");
    // wake_up_process(kthread);
    
    // rdtsc();
    
    /* Create the /proc file */
    if(!proc_create(PROCFS_NAME, 0, NULL, &sysemu_proc_fops)) {
        PRINT("Error: Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    PRINT("/proc/%s created\n", PROCFS_NAME);
    /*---------------------------------------*/
    
    return 0;
}

static void __exit lattop_module_exit(void){
    unregister_kprobe(&kp_activate_task);
    unregister_kprobe(&kp_deactivate_task);
    remove_proc_entry(PROCFS_NAME, NULL);
    // kthread_stop(kthread);
}

module_init(lattop_module_init)
module_exit(lattop_module_exit)
MODULE_LICENSE("GPL");
