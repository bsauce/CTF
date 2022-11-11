#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/seq_file.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include <asm/ftrace.h>

MODULE_AUTHOR("D3v17");
MODULE_LICENSE("GPL");

extern struct syscall_metadata *syscall_nr_to_meta(int nr);
extern const char *get_syscall_name(int syscall_nr);

static int get_syscall_nr(char *sc);
static int update_filter(char *syscalls);
static int cormon_proc_open(struct inode *inode, struct  file *file);
static ssize_t cormon_proc_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos); 
static void *cormon_seq_start(struct seq_file *seqfile, loff_t *pos);
static void *cormon_seq_next(struct seq_file *seqfile, void *v, loff_t *pos);
static void cormon_seq_stop(struct seq_file *seqfile, void *v);
static int cormon_seq_show(struct seq_file *f, void *ppos);
static int init_procfs(void);
static void cleanup_procfs(void);

DECLARE_PER_CPU(u64[NR_syscalls], __per_cpu_syscall_count);

static uint8_t filter[NR_syscalls];
static struct proc_dir_entry *cormon;
static char initial_filter[] = "sys_execve,sys_execveat,sys_fork,sys_keyctl,sys_msgget,sys_msgrcv,sys_msgsnd,sys_poll,sys_ptrace,sys_setxattr,sys_unshare";


static const struct proc_ops cormon_proc_ops = {
    .proc_open  = cormon_proc_open,
    .proc_read  = seq_read,
    .proc_write = cormon_proc_write
};


static struct seq_operations cormon_seq_ops = {
    .start  = cormon_seq_start,
    .next   = cormon_seq_next,
    .stop   = cormon_seq_stop,
    .show   = cormon_seq_show
};


static int get_syscall_nr(char *sc)
{
    struct syscall_metadata *entry;
    int nr;

    for (nr = 0; nr < NR_syscalls; nr++)
    {
        entry = syscall_nr_to_meta(nr);

        if (!entry)
            continue;

        if (arch_syscall_match_sym_name(entry->name, sc))
            return nr;
    }

    return -EINVAL;
}


static int update_filter(char *syscalls)
{
    uint8_t new_filter[NR_syscalls] = { 0 };
    char *name;
    int nr;

    while ((name = strsep(&syscalls, ",")) != NULL || syscalls != NULL)
    {
        nr = get_syscall_nr(name);

        if (nr < 0)
        {
            printk(KERN_ERR "[CoRMon::Error] Invalid syscall: %s!\n", name);
            return -EINVAL;
        }

        new_filter[nr] = 1;
    }

    memcpy(filter, new_filter, sizeof(filter));

    return 0;
}


static int cormon_proc_open(struct inode *inode, struct  file *file)
{
    return seq_open(file, &cormon_seq_ops);
}


static ssize_t cormon_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    loff_t offset = *ppos;
    char *syscalls;
    size_t len;

    if (offset < 0)
        return -EINVAL;

    if (offset >= PAGE_SIZE || !count)
        return 0;

    len = count > PAGE_SIZE ? PAGE_SIZE - 1 : count;

    syscalls = kmalloc(PAGE_SIZE, GFP_ATOMIC);
    printk(KERN_INFO "[CoRMon::Debug] Syscalls @ %#llx\n", (uint64_t)syscalls);

    if (!syscalls)
    {
        printk(KERN_ERR "[CoRMon::Error] kmalloc() call failed!\n");
        return -ENOMEM;
    }

    if (copy_from_user(syscalls, ubuf, len))
    {
        printk(KERN_ERR "[CoRMon::Error] copy_from_user() call failed!\n");
        return -EFAULT;
    }

    syscalls[len] = '\x00';

    if (update_filter(syscalls))
    {
        kfree(syscalls);
        return -EINVAL;
    }

    kfree(syscalls);

    return count;
}


static void *cormon_seq_start(struct seq_file *s, loff_t *pos)
{
    return *pos > NR_syscalls ? NULL : pos;
}


static void *cormon_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return (*pos)++ > NR_syscalls ? NULL : pos;
}


static void cormon_seq_stop(struct seq_file *s, void *v)
{
    return;
}


static int cormon_seq_show(struct seq_file *s, void *pos)
{
    loff_t nr = *(loff_t *)pos;
    const char *name;
    int i;

    if (nr == 0)
    {
        seq_putc(s, '\n');

        for_each_online_cpu(i)
            seq_printf(s, "%9s%d", "CPU", i);

        seq_printf(s, "\tSyscall (NR)\n\n");
    }

    if (filter[nr])
    {
        name = get_syscall_name(nr);

        if (!name)
            return 0;

        for_each_online_cpu(i)
            seq_printf(s, "%10llu", per_cpu(__per_cpu_syscall_count, i)[nr]);

        seq_printf(s, "\t%s (%lld)\n", name, nr);
    }

    if (nr == NR_syscalls)
        seq_putc(s, '\n');

    return 0;
}


static int init_procfs(void)
{
    printk(KERN_INFO "[CoRMon::Init] Initializing module...\n");

    cormon = proc_create("cormon", 0666, NULL, &cormon_proc_ops);

    if (!cormon)
    {
        printk(KERN_ERR "[CoRMon::Error] proc_create() call failed!\n");
        return -ENOMEM;
    }

    if (update_filter(initial_filter))
        return -EINVAL;

    printk(KERN_INFO "[CoRMon::Init] Initialization complete!\n");

    return 0;
}


static void cleanup_procfs(void)
{
    printk(KERN_INFO "[CoRMon::Exit] Cleaning up...\n");

    remove_proc_entry("cormon", NULL);

    printk(KERN_INFO "[CoRMon::Exit] Cleanup done, bye!\n");
}


module_init(init_procfs);
module_exit(cleanup_procfs);