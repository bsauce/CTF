#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>

MODULE_LICENSE("Dual BSD/GPL");
#define READ_ANY  0x1337
#define WRITE_ANY 0xdead
#define ADD_ANY   0xbeef
#define DEL_ANY   0x2333

struct in_args{
    uint64_t addr;
    uint64_t size;
    char __user *buf;
};


static long read_any(struct in_args *args){
    long ret = 0;
    char *addr = (void *)args->addr;
    if(copy_to_user(args->buf,addr,args->size)){
        return -EINVAL;
    }
    return ret;
}
static long write_any(struct in_args *args){
    long ret = 0;
    char *addr = (void *)args->addr;
    if(copy_from_user(addr,args->buf,args->size)){
        return -EINVAL;
    }
    return ret;
}
static long add_any(struct in_args *args){
    long ret = 0;
    char *buffer = kmalloc(args->size,GFP_KERNEL);
    if(buffer == NULL){
        return -ENOMEM;
    }
    if(copy_to_user(args->buf,&buffer,0x8)){  // (void *)buffer
        return -EINVAL;
    }
    return ret;
}
static long del_any(struct in_args *args){
    long ret = 0;
    kfree((void *)args->addr);
    return ret;
}
static long kpwn_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    long ret = -EINVAL;
    struct in_args in;
    if(copy_from_user(&in,(void *)arg,sizeof(in))){
        return ret;
    }
    switch(cmd){
        case READ_ANY:
            ret = read_any(&in);
            break;
        case WRITE_ANY:
            ret = write_any(&in);
            break;
        case DEL_ANY:
            ret = del_any(&in);
            break;
        case ADD_ANY:
            ret = add_any(&in);
            break;
        default:
            ret = -1;
    }
    return ret;
}
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open =      NULL,
    .release =   NULL,
    .read =      NULL,
    .write =     NULL,
    .unlocked_ioctl = kpwn_ioctl
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "kpwn",
    .fops = &fops
};

int kpwn_init(void)
{
    misc_register(&misc);
    return 0;
}

void kpwn_exit(void)
{
    printk(KERN_INFO "Goodbye hackern");
    misc_deregister(&misc);
}
module_init(kpwn_init);
module_exit(kpwn_exit);