#include <stdlib.h>

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/attrs.h"
#include "nest/mpls.h"
#include "conf/conf.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "lib/unaligned.h"

#include "proto/bgp/bgp.h"


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    struct bgp_write_state s;
    memset(&s, 0, sizeof(s));

    if (Size >= 7) {
      s.mp_reach = Data[0];
      s.as4_session = Data[1];
      s.add_path = Data[2];
      s.mpls = Data[3];
      s.sham = Data[4];
    }

    size_t max_attrs = 16;
    size_t attr_size = sizeof(eattr);
    size_t max_possible = Size / attr_size;
    size_t count = max_attrs < max_possible ? max_attrs : max_possible;

    ea_list *ealist = malloc(sizeof(ea_list) + count * sizeof(eattr));
    if (!ealist)
        return 0;

    ealist->count = (word)count;
    ealist->flags = 0;
    ealist->rfu = 0;
    ealist->next = NULL;

    attr_size = 8;

    for (size_t i = 0; i < count; i++) {
        size_t offset = i * attr_size;

        if (offset + attr_size <= Size) {
            const uint8_t *pos = Data + offset;

            ealist->attrs[i].id = (word)(pos[0] | (pos[1] << 8));
            ealist->attrs[i].flags = pos[2];

            uint8_t bitfield = pos[3];
            ealist->attrs[i].type = bitfield & 0x1F;
            ealist->attrs[i].originated = (bitfield >> 5) & 1;
            ealist->attrs[i].fresh = (bitfield >> 6) & 1;
            ealist->attrs[i].undef = (bitfield >> 7) & 1;

            uintptr_t data_val =
                ((uintptr_t)pos[4]) |
                ((uintptr_t)pos[5] << 8) |
                ((uintptr_t)pos[6] << 16) |
                ((uintptr_t)pos[7] << 24);

            ealist->attrs[i].u.data = data_val;

        } else {
            memset(&ealist->attrs[i], 0, sizeof(eattr));
        }

    }
    uint8_t buf[4096];
    uint8_t *end = buf + sizeof(buf);

    bgp_encode_attrs(&s, ealist, buf, end);

    free(ealist);
    return 0;
}
