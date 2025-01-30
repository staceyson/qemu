#ifndef HW_IOCAP_IOCAP_KEYMNGR_H
#define HW_IOCAP_IOCAP_KEYMNGR_H

#include "qemu/osdep.h"
#include "hw/iocap/iocap.h"
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
    union
    {
        struct
        {
            uint64_t good_reads;
            uint64_t bad_reads;
            uint64_t good_writes;
            uint64_t bad_writes;
        };
        uint8_t perf_bytes[32] __attribute__((aligned(8)));
    };

};

DeviceState *iocap_keymngr_create(hwaddr);

// Bit of a hack:
// calls into a global singleton IOCapKeymngr
// (we assume there is only ever one in the system)
// and checks the capability signature against the key data it stores.
// If the iocap_keymngr is present, the signature's correct, and the permissions match,
// the relevant performance counters (good_reads and/or good_writes) are incremented by one each and 'true' is returned.
// If the iocap_keymngr is present but the signature is not correct or the permissions don't match
// the relevant performance counters (bad_reads and/or bad_writes) are incremented by one each and 'false' is returned.
// If the iocap_keymngr is not present 'true' is always returned - the access will always be allowed.
// Note that if CCapPerms_ReadWrite is used and the cap only allows one of those,
// one 'good' and one 'bad' perf counter will increment.
// TODO allow checking the range as well?
bool iocap_keymngr_check_cap_signature(const CCap2024_11* cap, CCapPerms access_mode);

#endif
