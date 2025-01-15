#ifndef HW_IOCAP_IOCAP_KEYMNGR_H
#define HW_IOCAP_IOCAP_KEYMNGR_H

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_IOCAP_KEYMNGR "iocap_keymngr"
typedef struct IOCapKeymngrState IOCapKeymngrState;
DECLARE_INSTANCE_CHECKER(IOCapKeymngrState, IOCAP_KEYMNGR, TYPE_IOCAP_KEYMNGR)

struct IOCapKeymngrState {
	SysBusDevice parent_obj;
	MemoryRegion iomem;
	bool      key_en[ 0x100];
    uint8_t key_data[0x1000];
};

DeviceState *iocap_keymngr_create(hwaddr);

#endif
