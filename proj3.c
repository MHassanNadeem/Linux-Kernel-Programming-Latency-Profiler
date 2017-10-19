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
#define ERROR(msg, ...)         printk(KERN_ERR "ERROR: "msg, ##__VA_ARGS__)

/*---------------------------------------------------------------------------*/
/* Stack Implementation */
/*---------------------------------------------------------------------------*/
struct IntList{
    void* data;
    struct list_head list;
};

static int stack_push(struct list_head *head, void *data){
    struct IntList *tmp;

    tmp = (struct IntList*)kmalloc(sizeof(struct IntList), GFP_ATOMIC);
    if(tmp == NULL) goto error;
    tmp->data = data;
    list_add(&tmp->list, head);
    return 0;
    
    error:
        kfree(tmp);
        return -ENOMEM;
}

static inline int stack_isEmpty(struct list_head *head){
    return list_empty(head);
}

static void* stack_pop(struct list_head *head){
    struct IntList *listNode;
    void *data;
    listNode = list_first_entry(head, struct IntList, list);
    list_del(&listNode->list);
    data = listNode->data;
    kfree(listNode);
    return data;
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/* Queue Implementation */
/*---------------------------------------------------------------------------*/
static inline int enqueue(struct list_head *head, void *data){
    stack_push(head, data);
}

static inline int queue_isEmpty(struct list_head *head){
    return list_empty(head);
}

static void* dequeue(struct list_head *head){
    struct IntList *listNode;
    void *data;
    listNode = list_last_entry(head, struct IntList, list);
    list_del(&listNode->list);
    data = listNode->data;
    kfree(listNode);
    return data;
}
/*---------------------------------------------------------------------------*/

LIST_HEAD(queue);

// Concurrent access

/* Data Structures */
typedef enum {START_SLEEP, STOP_SLEEP} SchedEvent;

#define STACK_STR_LEN 1024
#define STACK_LEN     16

struct processID{
    pid_t pid; // Needs to be at the top
    unsigned long stack_entries[STACK_LEN]; // Needs to be 2nd
    struct stack_trace trace;
    char comm[TASK_COMM_LEN];
};

struct myData{
    struct processID id;
    unsigned long long sleepTime;
    unsigned long long dequeueTime;
    unsigned long long timeStamp;
    SchedEvent event;
};

void printStack(struct myData *data){
    char buffer[STACK_STR_LEN];
    
    snprint_stack_trace(buffer, STACK_STR_LEN, &data->id.trace, 1);
}

struct myData *newMyData(void){
    struct myData *data = (struct myData *) kmalloc(sizeof(struct myData), GFP_ATOMIC);
    if(data == NULL) return NULL;
    
    /* Fill any struct padding with zeros for consistent hashing */
    memset(
        (char*)&data->id.pid + sizeof(data->id.pid), // Start of padding
        0,
        (char*)&data->id.stack_entries - (char*)&data->id.pid - sizeof(data->id.pid) // Size of padding
    );
    
    /* init trace */
    data->id.trace.nr_entries = 0;
    data->id.trace.entries = data->id.stack_entries;
    data->id.trace.max_entries = STACK_LEN;
    data->id.trace.skip = 0;
    
    return data;
}

void freeMyData(struct myData *data){
    kfree(data);
}

DEFINE_HASHTABLE(int_hashtable, 14); /* 2^14 buckets */ // FIX ME

struct int_hashtableEntry{
    struct rb_node     rbnode;
    struct hlist_node  hnode;
    struct myData      *data;
    bool               isInTree;
};

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

struct rb_root rbRoot = RB_ROOT;

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

/* Will either return existing myData struct if found, else return a new struct */
static inline bool getAppropriateStruct(struct int_hashtableEntry **htEntry, struct task_struct *task){
    struct myData *tmpData = newMyData();
    
    tmpData->id.pid = task->pid;
    updateStackTrace(task, tmpData);
    
    *htEntry = hashtable_search(tmpData);
    if(*htEntry == NULL){
        // strcpy(tmpData->comm, task->comm); printStack(tmpData); // Debug
        strcpy(tmpData->id.comm, task->comm);
        *htEntry = (struct int_hashtableEntry *) kmalloc(sizeof(struct int_hashtableEntry), GFP_ATOMIC);
        (*htEntry)->data = tmpData;
        (*htEntry)->isInTree = false;
        return false;
    }else{
        kfree(tmpData);
        return true;
    }
}

static inline int getTaskStruct(struct task_struct *task){
    struct myData *tmpData = newMyData();
    if(tmpData == NULL) return NULL;
    
    tmpData->id.pid = task->pid;
    strcpy(tmpData->id.comm, task->comm);
    updateStackTrace(task, tmpData);
    
    return tmpData;
}


// dequeue/deactivate
static inline int task_start_sleep(struct task_struct *task, unsigned long long time){
    struct myData *tmpData = newMyData();
    tmpData->id.pid = task->pid;
    strcpy(tmpData->id.comm, task->comm);
    updateStackTrace(task, tmpData);
    tmpData->timeStamp = time;
    tmpData->event = START_SLEEP;
    /*********************/
    struct int_hashtableEntry *htEntry;
    
    if(getAppropriateStruct(&htEntry, task) == false){
        /* New struct, need to add it to hashtable */
        hash_add(int_hashtable, &htEntry->hnode, getHash(htEntry->data));
        enqueue(&queue, NULL);
    }
    
    htEntry->data->dequeueTime = time;
    
    return 0;
}

// enqueue/Activate
static inline int task_stop_sleep(struct task_struct *task, unsigned long long time){
    struct int_hashtableEntry *htEntry;

    /* If the struct was not already there */
    if(getAppropriateStruct(&htEntry, task) == false){
        freeMyData(htEntry->data);
        kfree(htEntry);
        return 0;
    }
    
    htEntry->data->sleepTime += (time - htEntry->data->dequeueTime);
    // DBG(htEntry->data->sleepTime, llu);
    
    if(htEntry->isInTree){
        // PRINT("old RB_NODE Deleted");
        // delete node
        rb_erase(&htEntry->rbnode, &rbRoot);
    }
    
    rbtree_insert(&rbRoot, htEntry);
    htEntry->isInTree = true;
    
    return 0;
}

void insertDumDum(unsigned long long val){
    struct myData *tmpData = newMyData();
    struct int_hashtableEntry *htEntry = (struct int_hashtableEntry *) kmalloc(sizeof(struct int_hashtableEntry), GFP_ATOMIC);
    
    tmpData->sleepTime = val;
    htEntry->data = tmpData;
    
    rbtree_insert(&rbRoot, htEntry);
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
    LIST_HEAD(stack);
    char *buffer = (char *) kmalloc(sizeof(char) * STACK_STR_LEN, GFP_ATOMIC);
    struct myData *data;
    bool done = false;
    
    struct rb_node *cursor = root->rb_node;
    
    while(!done){
        if(cursor != NULL){
            stack_push(&stack, cursor);
            cursor = cursor->rb_left;
        }else{
            if(!stack_isEmpty(&stack)){
                cursor = stack_pop(&stack);
                
                /* PRINT HERE */
                data = rb_entry(cursor, struct int_hashtableEntry, rbnode)->data;
                seq_printf(m, "-- %d - %s\n", data->id.pid, data->id.comm );
                seq_printf(m, "Sleep Time: %llu\n", data->sleepTime);
                snprint_stack_trace(buffer, STACK_STR_LEN, &data->id.trace, 1);
                seq_printf(m, "%s\n", buffer);
                
                cursor = cursor->rb_right;
            }else{
                done = true;
            }
        }
    }
    
    kfree(buffer);
}

/*********************************************************/
/* PROC */
/*********************************************************/
#define PROCFS_NAME         "lattop"

static int lattop_proc_show(struct seq_file *m, void *v){
    char *buffer = (char *) kmalloc(sizeof(char) * STACK_STR_LEN, GFP_ATOMIC);
    int i;
    struct int_hashtableEntry *tmp;
    struct hlist_node *tmp_hlist_node;
    
    seq_printf(m, "START\n");
    
    // hash_for_each_safe(int_hashtable, i, tmp_hlist_node, tmp, hnode){
        // seq_printf(m, "-- %d - %s\n", tmp->data->id.pid, tmp->data->comm );
        // seq_printf(m, "Sleep Time: %llu\n", tmp->data->sleepTime);
        // snprint_stack_trace(buffer, STACK_STR_LEN, &tmp->data->trace, 1);
        // seq_printf(m, "%s\n", buffer);
    // }
    
    rbTreePrinter(&rbRoot, m);
    
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


static struct task_struct *kthread = NULL;
int work_func(void *data){
    PRINT("Worker thread started");
    while(!kthread_should_stop()){
        if(queue_isEmpty(&queue)){
            schedule_timeout(100);
            // PRINT("Queue is empty");
        }else{
            dequeue(&queue);
            PRINT("dequeued");
        }
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
    
    /* TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT */
    // insertDumDum(5);
    // insertDumDum(1);
    // insertDumDum(6);
    // insertDumDum(2);
    // insertDumDum(3);
    /* TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT */
    
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
}

module_init(lattop_module_init)
module_exit(lattop_module_exit)
MODULE_LICENSE("GPL");
