#include "hw/iocap/iocap_keymngr.h"

#include "qapi/error.h" /* provides error_fatal() handler */
#include "qemu/log.h"

#define REG_ID 	0x0
#define PERF_COUNTER_GOOD_WRITE	0x1000
#define PERF_COUNTER_BAD_WRITE	0x1008
#define PERF_COUNTER_GOOD_READ	0x1010
#define PERF_COUNTER_BAD_READ	0x1018

static IOCapKeymngrState* singleton_iocap_keymngr = NULL;

static uint64_t iocap_keymngr_read(void *opaque, hwaddr addr, unsigned size)
{
    IOCapKeymngrState *s = opaque;

    if (size > 8 || (addr % 8) + size > 8) {
        // Too-big access or
        // Crossing an 8-byte boundary access
        return 0;
    }

    if (addr < 0x1000 && (addr % 16) == 0) {
        // Read key status
        hwaddr key_index = addr >> 4;
        return s->key_en[key_index];
    } else if (addr >= 0x1000 && addr + size <= 0x1020) {
        // Read performance counters
        uint64_t out = 0;
        for (unsigned i = 0; i < size; i++)
            out |= (s->perf_bytes[addr - 0x1000 + i] << (i * 8));
        return out;
    } else {
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
            s->key_data[addr - 0x1000 + b] = (data >> (b * 8)) & 0xFF;
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

    if (singleton_iocap_keymngr == NULL) {
        singleton_iocap_keymngr = s;
    } else {
        qemu_log("iocap: multiple instances of iocap_keymngr, global iocap_keymngr_check_cap_signature() may not work as expected\n");
    }
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

bool iocap_keymngr_check_cap_signature(const CCap2024_11* cap, CCapPerms access_mode)
{
    static bool have_logged[5] = { false };

    if (singleton_iocap_keymngr == NULL) {
        if (!have_logged[0])
            qemu_log("iocap: checking access when no iocap_keymngr present\n");
        have_logged[0] = true;
        return true;
    }

    uint32_t key_id;
    CCapResult res = ccap2024_11_read_secret_id(cap, &key_id);
    if (res != CCapResult_Success) {
        if (!have_logged[1])
            qemu_log("iocap: read_secret_id failed: %s\n", ccap_result_str(res));
        have_logged[1] = true;
        goto sig_fail;
    }

    key_id = key_id & 0xFF; // There are only 256 keys
    if (!singleton_iocap_keymngr->key_en[key_id]) {
        if (!have_logged[2])
            qemu_log("iocap: tried to use disabled key_id %d\n", key_id);
        have_logged[2] = true;
        goto sig_fail;
    }

    CCapU128 key = {0};
    memcpy(key, &singleton_iocap_keymngr->key_data[key_id * 16], 16);
    res = ccap2024_11_check_signature(cap, &key);
    if (res != CCapResult_Success) {
        if (!have_logged[3])
            qemu_log(
                "iocap: check_signature (data %02x%02x%02x%02x) (sig %02x%02x%02x%02x) for key_id %d (%02x%02x%02x%02x) failed: %s\n",
                cap->data[3], cap->data[2], cap->data[1], cap->data[0],
                cap->signature[3], cap->signature[2], cap->signature[1],
                cap->signature[0], key_id, key[3], key[2], key[1], key[0],
                ccap_result_str(res));
        have_logged[3] = true;
        goto sig_fail;
    }

    CCapPerms perms;
    res = ccap2024_11_read_perms(cap, &perms);
    if (res != CCapResult_Success) {
        if (!have_logged[4])
            qemu_log("iocap: read_perms failed: %s\n", ccap_result_str(res));
        have_logged[4] = true;
        goto sig_fail;
    }

    // The signature is correct and we know the permissions of the access.
    if (access_mode & CCapPerms_Read) {
        if (perms & CCapPerms_Read) {
            singleton_iocap_keymngr->good_reads++;
        } else {
            singleton_iocap_keymngr->bad_reads++;
        }
    }
    if (access_mode & CCapPerms_Write) {
        if (perms & CCapPerms_Write) {
            singleton_iocap_keymngr->good_writes++;
        } else {
            singleton_iocap_keymngr->bad_writes++;
        }
    }

    // qemu_log(
    //     "iocap: gr %lu br %lu gw %lu bw %lu\n",
    //     singleton_iocap_keymngr->good_reads,
    //     singleton_iocap_keymngr->bad_reads,
    //     singleton_iocap_keymngr->good_writes,
    //     singleton_iocap_keymngr->bad_writes
    // );

    return true;

sig_fail:
    if (access_mode & CCapPerms_Read) {
        singleton_iocap_keymngr->bad_reads++;
    }
    if (access_mode & CCapPerms_Write) {
        singleton_iocap_keymngr->bad_writes++;
    }
    return false;
}
