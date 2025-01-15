#include "hw/iocap/iocap_keymngr.h"

#include "qapi/error.h" /* provides error_fatal() handler */
#include "qemu/log.h"

#define REG_ID 	0x0
#define PERF_COUNTER_GOOD_WRITE	0x1000
#define PERF_COUNTER_BAD_WRITE	0x1008
#define PERF_COUNTER_GOOD_READ	0x1010
#define PERF_COUNTER_BAD_READ	0x1018

static uint64_t iocap_keymngr_read(void *opaque, hwaddr addr, unsigned size)
{
	IOCapKeymngrState *s = opaque;

    if (size > 8 || (addr % 8) + size > 8) {
        // Too-big access or
        // Crossing an 8-byte boundary access
        return 0;
    }

    if (addr < 0x1000 && (addr % 16) == 0) {
        hwaddr key_index = addr >> 4;
        return s->key_en[key_index];
    } else {
        // Performance counters, don't use them for now
        return 0;
    }
}

static void iocap_keymngr_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
	IOCapKeymngrState *s = opaque;

    if (size > 8 || (addr % 8) + size > 8) {
        // Too-big access or
        // Crossing an 8-byte boundary access
        return;
    }

    if (addr < 0x1000 && (addr % 16) == 0) {
        hwaddr key_index = addr >> 4;
        bool enabling_key = data & 1;

        if (enabling_key && !s->key_en[key_index]) {
            qemu_log(
                "iocap: enabling key %ld with data 0x%02x%02x%02x%02x%02x%02x%02x%02x_%02x%02x%02x%02x%02x%02x%02x%02x\n",
                key_index,
                s->key_data[addr + 15],
                s->key_data[addr + 14],
                s->key_data[addr + 13],
                s->key_data[addr + 12],
                s->key_data[addr + 11],
                s->key_data[addr + 10],
                s->key_data[addr + 9],
                s->key_data[addr + 8],
                s->key_data[addr + 7],
                s->key_data[addr + 6],
                s->key_data[addr + 5],
                s->key_data[addr + 4],
                s->key_data[addr + 3],
                s->key_data[addr + 2],
                s->key_data[addr + 1],
                s->key_data[addr]
            );
        }

        s->key_en[key_index] = enabling_key;
    } else if (addr < 0x2000) {
        for (int b = 0; b < size; b++) {
            s->key_data[addr - 0x1000 + b] = (data >> b) & 0x00;
        }
    } else {
        // Invalid address
    }
}

static const MemoryRegionOps iocap_keymngr_ops = {
	.read = iocap_keymngr_read,
    .write = iocap_keymngr_write,
	.endianness = DEVICE_NATIVE_ENDIAN,
};

static void iocap_keymngr_instance_init(Object *obj)
{
	IOCapKeymngrState *s = IOCAP_KEYMNGR(obj);

	/* allocate memory map region */
	memory_region_init_io(&s->iomem, obj, &iocap_keymngr_ops, s, TYPE_IOCAP_KEYMNGR, 0x2000);
	sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}

/* create a new type to define the info related to our device */
static const TypeInfo iocap_keymngr_info = {
	.name = TYPE_IOCAP_KEYMNGR,
	.parent = TYPE_SYS_BUS_DEVICE,
	.instance_size = sizeof(IOCapKeymngrState),
	.instance_init = iocap_keymngr_instance_init,
};

static void iocap_keymngr_register_types(void)
{
    type_register_static(&iocap_keymngr_info);
}

type_init(iocap_keymngr_register_types)

/*
 * Create the IOCap Key Manager device.
 */
DeviceState *iocap_keymngr_create(hwaddr addr)
{
	DeviceState *dev = qdev_new(TYPE_IOCAP_KEYMNGR);
	sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
	sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);
	return dev;
}