#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

/* Bit masks for meaningful bits in the CR0 control register. */
#define CR0_PE 1u            /* (PE) Protected-mode enable */
#define CR0_MP (1U << 1)     /* (MP) Monitor co-processor  */
#define CR0_EM (1U << 2)     /* (EM) x87 FPU Emulation */
#define CR0_TS (1U << 3)     /* (TS) Task switched  */
#define CR0_ET (1U << 4)     /* (ET) Extension type */
#define CR0_NE (1U << 5)     /* (NE) Numeric error  */
#define CR0_WP (1U << 16)    /* (WP) Write protect  */
#define CR0_AM (1U << 18)    /* (AM) Alignment mask */
#define CR0_NW (1U << 29)    /* (NW) Not-write through */
#define CR0_CD (1U << 30)    /* (CD) Cache disable */
#define CR0_PG (1U << 31)    /* (PG) Paging */

/* Bit masks for meaningful bits in the CR4 control register. */
#define CR4_VME 1               /* (VME) Virtual 8086 Mode Extensions */
#define CR4_PVI (1U << 1)       /* (PVI) Protected-mode Virtual Interrupts */
#define CR4_TSD (1U << 2)       /* (TSD) Time Stamp Disable */
#define CR4_DE  (1U << 3)       /* (DE)  Debugging Extensions */
#define CR4_PSE (1U << 4)       /* (PSE) Page Size Extension  */
#define CR4_PAE (1U << 5)       /* (PAE) Physical Address Extension */
#define CR4_MCE (1U << 6)       /* (MCE) Machine Check Exception */
#define CR4_PGE (1U << 7)       /* (PGE) Page Global Enabled */
#define CR4_PCE (1U << 8)       /* (PCE) Performance-Monitoring Counter enable */
#define CR4_OSFXSR (1U << 8)    /* (OSFXSR) Operating system support for FXSAVE and FXRSTOR instructions */
#define CR4_OSXMMEXCPT (1U << 10)    /* (OSXMMEXCPT) Operating System Support for Unmasked SIMD Floating-Point Exceptions */
#define CR4_UMIP (1U << 11)          /* (UMIP) User-Mode Instruction Prevention  */
#define CR4_VMXE (1U << 13)          /* (VMXE) Virtual Machine Extensions Enable */
#define CR4_SMXE (1U << 14)          /* (SMXE) Safer Mode Extensions Enable */
#define CR4_FSGSBASE (1U << 16)      /* (FSGSBASE) Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE */
#define CR4_PCIDE    (1U << 17)      /* (PCIDE) PCID Enable */
#define CR4_OSXSAVE  (1U << 18)      /* (OSXSAVE) XSAVE and Processor Extended States Enable */
#define CR4_SMEP (1U << 20)          /* (SMEP) Supervisor Mode Execution Protection Enable */
#define CR4_SMAP (1U << 21)          /* (SMAP) Supervisor Mode Access Prevention Enable */

/* Bit masks for meaningful bits in the Extended Feature Enable Register (EFER). */
#define EFER_SCE 1             /* SYSCALL enable bit */
#define EFER_LME (1U << 8)     /* IA-32e Mode (or long mode) Enable */
#define EFER_LMA (1U << 10)    /* IA-32e Mode Active (status bit) */
#define EFER_NXE (1U << 11)    /* Execute Disable Bit Enable (NX) */

/* 32-bit Page Directory Entry (PDE) bits. */
#define PDE32_PRESENT 1         /* (PRESENT) The PDE is valid/present */
#define PDE32_RW (1U << 1)      /* (RW) Read/write permission (1); Read-only (0) */
#define PDE32_USER (1U << 2)    /* (USER) Privilege level. 1 (user-mode); 0 (supervisor mode) */
#define PDE32_PS (1U << 7)      /* (PS) Page Size */

/* 64-bit Page Directory Entry (PDE) bits. */
#define PDE64_PRESENT 1             /* (PRESENT) */
#define PDE64_RW (1U << 1)          /* (RW) */
#define PDE64_USER (1U << 2)        /* (USER) */
#define PDE64_ACCESSED (1U << 5)    /* (ACCESSED) */
#define PDE64_DIRTY (1U << 6)       /* (DIRTY) */
#define PDE64_PS (1U << 7)          /* (PS) */
#define PDE64_G (1U << 8)           /* (G) */


/* Host-side representation of the VM created here. */
struct vm {
	int   sys_fd;    /* File descriptor for /dev/kvm. */
	int   fd;        /* File descriptor for the KVM virtual machine. */
	char *mem;       /* Pointer to the memory region that the program maps for the guest's memory. */
};

/* Host-side representation of the vCPU created for this VM. */
struct vcpu {
	int fd;      /* File descriptor representing the created VCPU. */
	struct kvm_run *kvm_run;    /* [?] */
};


/* Performs initial setup of a VM. */
void vm_init(struct vm *vm, size_t mem_size)
{
	/* KVM API Version */
	int api_ver;

	/* This struct describes the mapping between a 
		 region of the host process's virtual memory 
		 and a region of the guest's physical address 
		 space.
	 */
	struct kvm_userspace_memory_region memreg;

	/* [STEP 1]: Open a handle to the kernel's kvm interface. */
	vm->sys_fd = open("/dev/kvm", O_RDWR);
	if (vm->sys_fd < 0) {
		perror("open /dev/kvm");
		exit(1);
	}

	/* [STEP 2]: Query the KVM API version. */
	api_ver = ioctl(vm->sys_fd, KVM_GET_API_VERSION, 0);
	if (api_ver < 0) {
		perror("KVM_GET_API_VERSION");
		exit(1);
	}

	/* [STEP 3]: Verify the API version. */
	if (api_ver != KVM_API_VERSION) {
		fprintf(
			stderr, "Got KVM api version %d, expected %d\n",
			api_ver, KVM_API_VERSION
		);
		exit(1);
	}

	/* [STEP 4]: Create a virtual machine.

		KVM_CREATE_VM creates the resources needed to 
		represent a VM inside the kernel and gives 
		userspace a handle to them.
	*/
	vm->fd = ioctl(vm->sys_fd, KVM_CREATE_VM, 0);
	if (vm->fd < 0) {
		perror("KVM_CREATE_VM");
		exit(1);
	}

	/* [STEP 5]: [?] */
	if (
		ioctl(vm->fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0
	){
		perror("KVM_SET_TSS_ADDR");
		exit(1);
	}

	/* [STEP 6]: Reserve host's userspace memory that 
			will be used as the guest's physical memory. */
	vm->mem = mmap(
		NULL, 
		mem_size, 
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0
	);
	if (vm->mem == MAP_FAILED) {
		perror("mmap mem");
		exit(1);
	}

	/* A hint to the kernel to enable KSM. */
	madvise(vm->mem, mem_size, MADV_MERGEABLE);

	/* [STEP 7]: Set the values in memreg. */

	/* Where the memory exists in the host process? */
	memreg.userspace_addr = (unsigned long)vm->mem;

	/* Where the host process's memory appears in 
		 the guest's physical address space? */
	memreg.guest_phys_addr = 0;

	/* The size of the memory. */
	memreg.memory_size = mem_size;

	memreg.slot = 0;     /* # guest memory region. */
	memreg.flags = 0;    /* [?] */

	/* [STEP 8]: Pass the updated memreg description 
			to KVM. */
	if (
		ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0
	){
		perror("KVM_SET_USER_MEMORY_REGION");
		exit(1);
	}
}

/* Create and initialize a vCPU. */
void vcpu_init(struct vm *vm, struct vcpu *vcpu)
{
	int vcpu_mmap_size;

	vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, 0);
        if (vcpu->fd < 0) {
		perror("KVM_CREATE_VCPU");
                exit(1);
	}

	vcpu_mmap_size = ioctl(vm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
        if (vcpu_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
                exit(1);
	}

	vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, vcpu->fd, 0);
	if (vcpu->kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		exit(1);
	}
}

int run_vm(struct vm *vm, struct vcpu *vcpu, size_t sz)
{
	struct kvm_regs regs;
	uint64_t memval = 0;

	for (;;) {
		if (ioctl(vcpu->fd, KVM_RUN, 0) < 0) {
			perror("KVM_RUN");
			exit(1);
		}

		switch (vcpu->kvm_run->exit_reason) {
		case KVM_EXIT_HLT:
			goto check;

		case KVM_EXIT_IO:
			if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
			    && vcpu->kvm_run->io.port == 0xE9) {
				char *p = (char *)vcpu->kvm_run;
				fwrite(p + vcpu->kvm_run->io.data_offset,
				       vcpu->kvm_run->io.size, 1, stdout);
				fflush(stdout);
				continue;
			}

			/* fall through */
		default:
			fprintf(stderr,	"Got exit_reason %d,"
				" expected KVM_EXIT_HLT (%d)\n",
				vcpu->kvm_run->exit_reason, KVM_EXIT_HLT);
			exit(1);
		}
	}

 check:
	if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}

	if (regs.rax != 42) {
		printf("Wrong result: {E,R,}AX is %lld\n", regs.rax);
		return 0;
	}

	memcpy(&memval, &vm->mem[0x400], sz);
	if (memval != 42) {
		printf("Wrong result: memory at 0x400 is %lld\n",
		       (unsigned long long)memval);
		return 0;
	}

	return 1;
}

extern const unsigned char guest16[], guest16_end[];

int run_real_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing real mode\n");

        if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	sregs.cs.selector = 0;
	sregs.cs.base = 0;

        if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;

	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest16, guest16_end-guest16);
	return run_vm(vm, vcpu, 2);
}

static void setup_protected_mode(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 1,
		.s = 1, /* Code/data */
		.l = 0,
		.g = 1, /* 4KB granularity */
	};

	sregs->cr0 |= CR0_PE; /* enter protected mode */

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

extern const unsigned char guest32[], guest32_end[];

int run_protected_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing protected mode\n");

        if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_protected_mode(&sregs);

        if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;

	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest32, guest32_end-guest32);
	return run_vm(vm, vcpu, 4);
}

static void setup_paged_32bit_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	uint32_t pd_addr = 0x2000;
	uint32_t *pd = (void *)(vm->mem + pd_addr);

	/* A single 4MB page to cover the memory region */
	pd[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS;
	/* Other PDEs are left zeroed, meaning not present. */

	sregs->cr3 = pd_addr;
	sregs->cr4 = CR4_PSE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = 0;
}

int run_paged_32bit_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 32-bit paging\n");

        if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_protected_mode(&sregs);
	setup_paged_32bit_mode(vm, &sregs);

        if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;

	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest32, guest32_end-guest32);
	return run_vm(vm, vcpu, 4);
}

extern const unsigned char guest64[], guest64_end[];

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 0,
		.s = 1, /* Code/data */
		.l = 1,
		.g = 1, /* 4KB granularity */
	};

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	uint64_t pml4_addr = 0x2000;
	uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

	uint64_t pdpt_addr = 0x3000;
	uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

	uint64_t pd_addr = 0x4000;
	uint64_t *pd = (void *)(vm->mem + pd_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
	pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

	sregs->cr3 = pml4_addr;
	sregs->cr4 = CR4_PAE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = EFER_LME | EFER_LMA;

	setup_64bit_code_segment(sregs);
}

int run_long_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 64-bit mode\n");

        if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_long_mode(vm, &sregs);

        if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest64, guest64_end-guest64);
	return run_vm(vm, vcpu, 8);
}


int main(int argc, char **argv)
{
	struct vm vm;
	struct vcpu vcpu;
	enum {
		REAL_MODE,
		PROTECTED_MODE,
		PAGED_32BIT_MODE,
		LONG_MODE,
	} mode = REAL_MODE;
	int opt;

	while ((opt = getopt(argc, argv, "rspl")) != -1) {
		switch (opt) {
		case 'r':
			mode = REAL_MODE;
			break;

		case 's':
			mode = PROTECTED_MODE;
			break;

		case 'p':
			mode = PAGED_32BIT_MODE;
			break;

		case 'l':
			mode = LONG_MODE;
			break;

		default:
			fprintf(stderr, "Usage: %s [ -r | -s | -p | -l ]\n",
				argv[0]);
			return 1;
		}
	}

	vm_init(&vm, 0x200000);
	vcpu_init(&vm, &vcpu);

	switch (mode) {
	case REAL_MODE:
		return !run_real_mode(&vm, &vcpu);

	case PROTECTED_MODE:
		return !run_protected_mode(&vm, &vcpu);

	case PAGED_32BIT_MODE:
		return !run_paged_32bit_mode(&vm, &vcpu);

	case LONG_MODE:
		return !run_long_mode(&vm, &vcpu);
	}

	return 1;
}
