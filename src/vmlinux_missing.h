#ifndef __VMLINUX_MISSING_H_
#define __VMLINUX_MISSING_H_

struct trace_event_raw_do_sys_open {
        struct trace_entry ent;
        u32 __data_loc_filename;
        int flags;
        int mode;
        char __data[0];
};

#endif
