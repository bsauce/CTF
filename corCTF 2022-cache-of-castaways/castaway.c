#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "castaway"
#define CLASS_NAME  "castaway"

#define OVERFLOW_SZ 0x6

#define CHUNK_SIZE 512
#define MAX 8 * 50

#define ALLOC 0xcafebabe
#define DELETE 0xdeadbabe
#define EDIT 0xf00dbabe

MODULE_DESCRIPTION("a castaway cache, a secluded slab, a marooned memory");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("FizzBuzz101");

typedef struct
{
    int64_t idx;
    uint64_t size;
    char *buf;    
}user_req_t;

int castaway_ctr = 0;

typedef struct
{
    char pad[OVERFLOW_SZ];
    char buf[];
}castaway_t;

struct castaway_cache
{
    char buf[CHUNK_SIZE];
};

static DEFINE_MUTEX(castaway_lock);

castaway_t **castaway_arr;

static long castaway_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static long castaway_add(void);
static long castaway_edit(int64_t idx, uint64_t size, char *buf);


static struct miscdevice castaway_dev;
static struct file_operations castaway_fops = {.unlocked_ioctl = castaway_ioctl};

static struct kmem_cache *castaway_cachep;

static long castaway_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    user_req_t req;
    long ret = 0;

    if (cmd != ALLOC && copy_from_user(&req, (void *)arg, sizeof(req)))
    {
        return -1;
    }
    mutex_lock(&castaway_lock);
    switch (cmd)
    {
        case ALLOC:
            ret = castaway_add();
            break;
        case EDIT:
            ret = castaway_edit(req.idx, req.size, req.buf);
            break;
        default:
            ret = -1;
    }
    mutex_unlock(&castaway_lock);
    return ret;
}

static long castaway_add(void)
{
    int idx;
    if (castaway_ctr >= MAX)
    {
        goto failure_add;
    }
    idx = castaway_ctr++;
    castaway_arr[idx] = kmem_cache_zalloc(castaway_cachep, GFP_KERNEL_ACCOUNT);

    if (!castaway_arr[idx])
    {
        goto failure_add;
    }

    return idx;

    failure_add:
    printk(KERN_INFO "castaway chunk allocation failed\n");
    return -1;
}

static long castaway_edit(int64_t idx, uint64_t size, char *buf)
{
    char temp[CHUNK_SIZE];
    if (idx < 0 || idx >= MAX || !castaway_arr[idx])
    {
        goto edit_fail;
    }
    if (size > CHUNK_SIZE || copy_from_user(temp, buf, size))
    {
        goto edit_fail;
    }
    memcpy(castaway_arr[idx]->buf, temp, size);

    return size;

    edit_fail:
    printk(KERN_INFO "castaway chunk editing failed\n");
    return -1;
}

static int init_castaway_driver(void)
{
    castaway_dev.minor = MISC_DYNAMIC_MINOR;
    castaway_dev.name = DEVICE_NAME;
    castaway_dev.fops = &castaway_fops;
    castaway_dev.mode = 0644;
    mutex_init(&castaway_lock);
    if (misc_register(&castaway_dev))
    {
        return -1;
    }
    castaway_arr = kzalloc(MAX * sizeof(castaway_t *), GFP_KERNEL);
    if (!castaway_arr)
    {
        return -1;
    }
    castaway_cachep = KMEM_CACHE(castaway_cache, SLAB_PANIC | SLAB_ACCOUNT);
    if (!castaway_cachep)
    {
        return -1;
    }
    printk(KERN_INFO "All alone in an castaway cache... \n");
    printk(KERN_INFO "There's no way a pwner can escape!\n");
    return 0;
}

static void cleanup_castaway_driver(void)
{
    int i;
    misc_deregister(&castaway_dev);
    mutex_destroy(&castaway_lock);
    for (i = 0; i < MAX; i++)
    {
        if (castaway_arr[i])
        {
            kfree(castaway_arr[i]);
        }
    }
    kfree(castaway_arr);
    printk(KERN_INFO "Guess you remain a castaway\n");
}

module_init(init_castaway_driver);
module_exit(cleanup_castaway_driver);