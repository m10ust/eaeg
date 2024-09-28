/* eaeg.c - Enhanced Advanced Entropy Generator (EAEG) Kernel Module */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/rtnetlink.h>    /* Include this header for rtnl_lock and rtnl_unlock */
#include <crypto/hash.h>

#define ENTROPY_POOL_SIZE 32   /* Increased size for better mixing */
#define MAX_TRACKED_IRQS 256   /* Track more IRQs for better entropy sources */
#define MIXING_INTERVAL 64     /* Mix more frequently for improved randomness */
#define SAMPLE_SIZE 1000       /* Number of samples to keep for each IRQ */

static u32 entropy_pool[ENTROPY_POOL_SIZE];
static int pool_index = 0;
static int inputs_since_mix = 0;

struct irq_info {
    int irq;
    u64 last_time;
    unsigned int count;
    u64 *samples;
    int sample_index;
};

static struct irq_info tracked_irqs[MAX_TRACKED_IRQS];
static int num_tracked_irqs = 0;

static DEFINE_SPINLOCK(entropy_lock);

/* Module parameters */
static int sample_size = SAMPLE_SIZE;
module_param(sample_size, int, 0644);
MODULE_PARM_DESC(sample_size, "Number of samples to keep for each IRQ");

static int initial_threshold_int = 200; /* 2.00 * 100 */
module_param(initial_threshold_int, int, 0644);
MODULE_PARM_DESC(initial_threshold_int, "Initial entropy threshold (multiplied by 100)");

/* Helper function to read CPU microspike using TSC (Time Stamp Counter) */
static inline u64 read_tsc(void)
{
    unsigned int lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
}

/* Function to read hardware RNG using RDRAND instruction (x86-specific) */
static inline u64 read_hardware_rng(void)
{
    u64 rand_val = 0;
    unsigned char ok;

    asm volatile("rdrand %0; setc %1"
                 : "=r"(rand_val), "=qm"(ok));

    if (!ok)
        rand_val = read_tsc(); /* Fallback to TSC if RDRAND fails */

    return rand_val;
}

/* Improved mixing function using SHA-512 and combining multiple hashes */
static void mix_pool(void)
{
    struct crypto_shash *sha512;
    struct shash_desc *shash;
    u8 hash_output[64];  /* SHA-512 output size in bytes */
    int i, ret;

    /* Allocate hash descriptor and SHA-512 transform */
    sha512 = crypto_alloc_shash("sha512", 0, 0);
    if (IS_ERR(sha512)) {
        pr_err("Failed to allocate SHA512 transform\n");
        return;
    }

    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(sha512), GFP_KERNEL);
    if (!shash) {
        pr_err("Failed to allocate SHA512 descriptor\n");
        crypto_free_shash(sha512);
        return;
    }

    shash->tfm = sha512;

    ret = crypto_shash_init(shash);
    if (ret) {
        pr_err("Failed to initialize SHA512 hashing: %d\n", ret);
        goto out_free;
    }

    /* Mix the entire entropy pool into the hash */
    ret = crypto_shash_update(shash, (u8 *)entropy_pool, sizeof(entropy_pool));
    if (ret) {
        pr_err("SHA512 update failed: %d\n", ret);
        goto out_free;
    }

    /* Include additional hardware RNG data if available */
    {
        u64 hw_rng = read_hardware_rng();
        ret = crypto_shash_update(shash, (u8 *)&hw_rng, sizeof(hw_rng));
        if (ret) {
            pr_err("SHA512 update with hardware RNG failed: %d\n", ret);
            goto out_free;
        }
    }

    ret = crypto_shash_final(shash, hash_output);
    if (ret) {
        pr_err("SHA512 finalization failed: %d\n", ret);
        goto out_free;
    }

    /* Apply the hash output back into the entropy pool */
    for (i = 0; i < ENTROPY_POOL_SIZE; i++) {
        entropy_pool[i] ^= ((u32 *)hash_output)[i % (sizeof(hash_output) / sizeof(u32))];
    }

    /* Feed the mixed pool back into the kernel entropy pool */
    add_device_randomness(entropy_pool, sizeof(entropy_pool));

out_free:
    kfree(shash);
    crypto_free_shash(sha512);
}

/* Modified add_entropy to incorporate microspike variations */
static void add_entropy(u32 value)
{
    unsigned long flags;
    u64 microspike = read_tsc();
    u64 hw_rng = read_hardware_rng();

    spin_lock_irqsave(&entropy_lock, flags);

    /* Mix the value, microspike, and hardware RNG into the entropy pool */
    entropy_pool[pool_index] ^= value ^ (u32)(microspike ^ (microspike >> 32)) ^ (u32)(hw_rng ^ (hw_rng >> 32));
    pool_index = (pool_index + 1) % ENTROPY_POOL_SIZE;
    inputs_since_mix++;

    if (inputs_since_mix >= MIXING_INTERVAL) {
        mix_pool();
        inputs_since_mix = 0;
    }

    spin_unlock_irqrestore(&entropy_lock, flags);
}

/* IRQ handler that adds entropy */
static irqreturn_t entropy_irq_handler(int irq, void *dev_id)
{
    struct irq_info *irq_info = (struct irq_info *)dev_id;
    u64 current_time = ktime_get_real_ns();
    u64 delta;

    if (irq_info->last_time != 0) {
        delta = current_time - irq_info->last_time;
        irq_info->samples[irq_info->sample_index] = delta;
        irq_info->sample_index = (irq_info->sample_index + 1) % sample_size;

        /* Combine delta with microspikes for additional entropy */
        add_entropy((u32)(delta ^ (delta >> 32)));
    }
    irq_info->last_time = current_time;
    irq_info->count++;

    return IRQ_HANDLED;
}

/* Function to add an interrupt source */
static int add_interrupt_source(int irq)
{
    int ret;

    if (num_tracked_irqs >= MAX_TRACKED_IRQS) {
        return -ENOSPC;
    }

    tracked_irqs[num_tracked_irqs].irq = irq;
    tracked_irqs[num_tracked_irqs].last_time = 0;
    tracked_irqs[num_tracked_irqs].count = 0;
    tracked_irqs[num_tracked_irqs].sample_index = 0;
    tracked_irqs[num_tracked_irqs].samples = kzalloc(sizeof(u64) * sample_size, GFP_KERNEL);
    if (!tracked_irqs[num_tracked_irqs].samples) {
        pr_err("Failed to allocate sample array for IRQ %d\n", irq);
        return -ENOMEM;
    }

    ret = request_irq(irq, entropy_irq_handler, IRQF_SHARED, "eaeg_irq",
                      &tracked_irqs[num_tracked_irqs]);
    if (ret) {
        pr_err("Failed to request IRQ %d: %d\n", irq, ret);
        kfree(tracked_irqs[num_tracked_irqs].samples);
        return ret;
    }

    num_tracked_irqs++;

    return 0;
}

/* Function to register selected IRQs */
static int register_selected_irqs(void)
{
    int ret;

    /* Register commonly used IRQs */
    ret = add_interrupt_source(1);  /* Keyboard */
    if (ret && ret != -ENOSPC)
        pr_err("Failed to add interrupt source 1: %d\n", ret);

    ret = add_interrupt_source(12); /* Mouse */
    if (ret && ret != -ENOSPC)
        pr_err("Failed to add interrupt source 12: %d\n", ret);

    /* Add other known IRQs as needed */
    ret = add_interrupt_source(19); /* Example IRQ */
    if (ret && ret != -ENOSPC)
        pr_err("Failed to add interrupt source 19: %d\n", ret);

    ret = add_interrupt_source(23); /* Example IRQ */
    if (ret && ret != -ENOSPC)
        pr_err("Failed to add interrupt source 23: %d\n", ret);

    return 0;
}

/* Network RX handler for adding entropy from network packets */
static rx_handler_result_t net_rx_handler(struct sk_buff **pskb)
{
    u64 current_time = ktime_get_real_ns();
    u64 microspike = read_tsc();
    u64 hw_rng = read_hardware_rng();
    u32 value = (u32)(current_time ^ microspike ^ hw_rng);

    add_entropy(value);

    return RX_HANDLER_PASS;
}

/* Function to register network hooks */
static int register_net_hooks(void)
{
    struct net_device *dev;
    int ret;

    rtnl_lock();
    for_each_netdev(&init_net, dev) {
        if (dev->netdev_ops && dev->netdev_ops->ndo_start_xmit) {
            ret = netdev_rx_handler_register(dev, net_rx_handler, NULL);
            if (ret)
                pr_err("Failed to register net RX handler for %s: %d\n", dev->name, ret);
        }
    }
    rtnl_unlock();

    return 0;
}

/* Function to unregister network hooks */
static void unregister_net_hooks(void)
{
    struct net_device *dev;

    rtnl_lock();
    for_each_netdev(&init_net, dev) {
        netdev_rx_handler_unregister(dev);
    }
    rtnl_unlock();
}

/* Module initialization function */
static int __init entropy_init(void)
{
    int ret;

    pr_info("Enhanced Advanced Entropy Generator (EAEG) module initialized\n");

    /* Initialize entropy_pool */
    get_random_bytes(entropy_pool, sizeof(entropy_pool));

    /* Register selected IRQs */
    ret = register_selected_irqs();
    if (ret)
        pr_err("Failed to register selected IRQs: %d\n", ret);

    /* Register network hooks */
    ret = register_net_hooks();
    if (ret)
        pr_err("Failed to register network hooks: %d\n", ret);

    return 0;
}

/* Module exit function */
static void __exit entropy_exit(void)
{
    int i;

    /* Unregister network hooks */
    unregister_net_hooks();

    /* Free IRQs and sample arrays */
    for (i = 0; i < num_tracked_irqs; i++) {
        free_irq(tracked_irqs[i].irq, &tracked_irqs[i]);
        kfree(tracked_irqs[i].samples);
    }

    pr_info("Enhanced Advanced Entropy Generator (EAEG) module exited\n");
}

module_init(entropy_init);
module_exit(entropy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M4Y0U");
MODULE_DESCRIPTION("Enhanced Advanced Entropy Generator (EAEG)");
