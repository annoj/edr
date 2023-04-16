#!/bin/bash

SYSCALLS=$(awk 'BEGIN { print "#include <sys/syscall.h>" } /p_syscall_meta/ { syscall = substr($NF, 19); printf "SYS_%s = \"%s\";\n", syscall, syscall }' /proc/kallsyms \
    | gcc -E -P - \
    | grep -v SYS_ \
    | sort -nu \
    | sed 's/\(.*\)\( =.*\)/\tsyscall_table[\1]\2/g')

NSYSCALLS=$(echo "$SYSCALLS" | tail -n1 | sed 's/.*\[\(.*\)\].*/\1/g')

cat <<EOF > syscall-table.h
const char *syscall_table[$NSYSCALLS + 1];

const char **init_syscall_table()
{

$SYSCALLS

return syscall_table;
}
EOF
