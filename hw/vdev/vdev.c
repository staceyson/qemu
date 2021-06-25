#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "hw/sysbus.h"
#include "chardev/char.h"
#include "hw/hw.h"
#include "hw/irq.h"
#include "hw/core/cpu.h"
#include "hw/vdev/vdev.h"
#include "sysemu/cpus.h"

#define	EPW_READ_ADDRESS		0x0000	/* read only */
#define	EPW_READ_FLIT_SIZE		0x0008	/* read only */
#define	EPW_READ_BURST_COUNT		0x000C	/* read only */
#define	EPW_READ_RESPONSE_DATA		0x0040	/* read/write */
#define	EPW_WRITE_ADDRESS		0x1000	/* read only */
#define	EPW_WRITE_BYTE_ENABLE		0x1008	/* read only */
#define	EPW_WRITE_DATA			0x1040	/* read only */
#define	EPW_TIME_STAMP			0x2000	/* read only */
#define	EPW_REQUEST_ID			0x2004	/* read only */
#define	EPW_REQUEST_IS_WRITE		0x2006	/* read only */
#define	EPW_REQUEST_LEVEL_SEND_RESPONSE	0x2007	/* read/write */
#define	EPW_ENABLE_DEVICE_EMULATION	0x2008	/* read/write */

struct epw_request {
	uint64_t addr;
	uint8_t is_write;
	uint64_t flit_size;
	uint32_t burst_count;
	uint32_t byte_enable;
	uint8_t data[32];
	uint64_t data64;
	uint8_t data_len;
	uint8_t pending;
};

static struct epw_request req;

static uint64_t
vdev_read(void *opaque, hwaddr addr, unsigned int size)
{
	CPUState *cpu;
	vdevState *s;

	s = opaque;

	req.is_write = 0;
	req.flit_size = 1;
	req.burst_count = 4;
	req.addr = addr;

	qemu_log_mask(LOG_GUEST_ERROR, "%s: read: addr=0x%x size=%d\n",
	    __func__, (int)addr,size);

	CPU_FOREACH(cpu) {
		//fprintf(stderr, "CPU #%d:\n", cpu->cpu_index);
		if (cpu->cpu_index == 0)
			cpu->stop = true;
	};

	cpu = current_cpu;

	return s->reg[addr];
}

static void
vdev_write(void *opaque, hwaddr addr, uint64_t val64, unsigned int size)
{
	unsigned char ch;
	uint32_t value;
	vdevState *s;

	/* dummy code for future development */
	s = opaque;
	value = val64;
	ch = value;

	req.is_write = 1;
	req.byte_enable = size;
	req.addr = addr;
	req.data64 = val64;

	qemu_log_mask(LOG_GUEST_ERROR, "%s: write: addr=0x%x v=0x%x\n",
	    __func__, (int)addr, (int)value);
}

static uint64_t
vdev_window_read(void *opaque, hwaddr addr, unsigned int size)
{

	return (0);
}

static void
vdev_window_write(void *opaque, hwaddr addr, uint64_t val64, unsigned int size)
{

}

static void
vdev_init(vdevState *s)
{

	s->reg[0]='B';
	s->reg[1]='U';
	s->reg[2]='T';
	s->reg[3]='T';
	s->reg[4]='E';
	s->reg[5]='R';
}

static const MemoryRegionOps vdev_ops = {
	.read = vdev_read,
	.write = vdev_write,
	.endianness = DEVICE_NATIVE_ENDIAN,
	.valid = {
		.min_access_size = 1,
		.max_access_size = 6
	}
};

static const MemoryRegionOps vdev_window_ops = {
	.read = vdev_window_read,
	.write = vdev_window_write,
	.endianness = DEVICE_NATIVE_ENDIAN,
	.valid = {
		.min_access_size = 1,
		.max_access_size = 6
	}
};

vdevState *
vdev_create(MemoryRegion *address_space, hwaddr base, hwaddr window)
{
	vdevState *s, *w;

	s = g_malloc0(sizeof(vdevState));
	vdev_init(s);
	memory_region_init_io(&s->mmio, NULL, &vdev_ops,
	    s, TYPE_VIRTUAL_DEVICE, 32);
	memory_region_add_subregion(address_space, base, &s->mmio);

	w = g_malloc0(sizeof(vdevState));
	vdev_init(w);
	memory_region_init_io(&w->mmio, NULL, &vdev_window_ops,
	    w, TYPE_VIRTUAL_DEVICE, 32);
	memory_region_add_subregion(address_space, window, &w->mmio);

	return (s);
}
