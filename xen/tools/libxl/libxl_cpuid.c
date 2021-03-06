/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <string.h>

#include "libxl.h"
#include "libxl_osdeps.h"
#include "libxl_internal.h"

void libxl_cpuid_destroy(libxl_cpuid_policy_list *p_cpuid_list)
{
    int i, j;
    libxl_cpuid_policy_list cpuid_list = *p_cpuid_list;

    if (cpuid_list == NULL)
        return;
    for (i = 0; cpuid_list[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++) {
        for (j = 0; j < 4; j++)
            if (cpuid_list[i].policy[j] != NULL)
                free(cpuid_list[i].policy[j]);
    }
    return;
}

#define CPUID_REG_INV 0
#define CPUID_REG_EAX 1
#define CPUID_REG_EBX 2
#define CPUID_REG_ECX 3
#define CPUID_REG_EDX 4

/* mapping CPUID features to names
 * holds a "name" for each feature, specified by the "leaf" number (and an
 * optional "subleaf" in ECX), the "reg"ister (EAX-EDX) used and a number of
 * bits starting with "bit" and being "length" bits long.
 * Used for the static structure describing all features.
 */
struct cpuid_flags {
    char* name;
    uint32_t leaf;
    uint32_t subleaf;
    int reg;
    int bit;
    int length;
};

/* go through the dynamic array finding the entry for a specified leaf.
 * if no entry exists, allocate one and return that.
 */
static libxl_cpuid_policy_list cpuid_find_match(libxl_cpuid_policy_list *list,
                                          uint32_t leaf, uint32_t subleaf)
{
    int i = 0;

    if (*list != NULL) {
        for (i = 0; (*list)[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++) {
            if ((*list)[i].input[0] == leaf && (*list)[i].input[1] == subleaf)
                return *list + i;
        }
    }
    *list = realloc(*list, sizeof((*list)[0]) * (i + 2));
    (*list)[i].input[0] = leaf;
    (*list)[i].input[1] = subleaf;
    memset((*list)[i].policy, 0, 4 * sizeof(char*));
    (*list)[i + 1].input[0] = XEN_CPUID_INPUT_UNUSED;
    return *list + i;
}

/* parse a single key=value pair and translate it into the libxc
 * used interface using 32-characters strings for each register.
 * Will overwrite earlier entries and thus can be called multiple
 * times.
 */
int libxl_cpuid_parse_config(libxl_cpuid_policy_list *cpuid, const char* str)
{
#define NA XEN_CPUID_INPUT_UNUSED
    struct cpuid_flags cpuid_flags[] = {
        {"maxleaf",      0x00000000, NA, CPUID_REG_EAX,  0, 32},
      /* the following two entries are subject to tweaking later in the code */
        {"family",       0x00000001, NA, CPUID_REG_EAX,  8,  8},
        {"model",        0x00000001, NA, CPUID_REG_EAX,  4,  8},
        {"stepping",     0x00000001, NA, CPUID_REG_EAX,  0,  4},
        {"localapicid",  0x00000001, NA, CPUID_REG_EBX, 24,  8},
        {"proccount",    0x00000001, NA, CPUID_REG_EBX, 16,  8},
        {"clflush",      0x00000001, NA, CPUID_REG_EBX,  8,  8},
        {"brandid",      0x00000001, NA, CPUID_REG_EBX,  0,  8},
        {"f16c",         0x00000001, NA, CPUID_REG_ECX, 29,  1},
        {"avx",          0x00000001, NA, CPUID_REG_ECX, 28,  1},
        {"osxsave",      0x00000001, NA, CPUID_REG_ECX, 27,  1},
        {"xsave",        0x00000001, NA, CPUID_REG_ECX, 26,  1},
        {"aes",          0x00000001, NA, CPUID_REG_ECX, 25,  1},
        {"popcnt",       0x00000001, NA, CPUID_REG_ECX, 23,  1},
        {"movbe",        0x00000001, NA, CPUID_REG_ECX, 22,  1},
        {"x2apic",       0x00000001, NA, CPUID_REG_ECX, 21,  1},
        {"sse4.2",       0x00000001, NA, CPUID_REG_ECX, 20,  1},
        {"sse4.1",       0x00000001, NA, CPUID_REG_ECX, 19,  1},
        {"dca",          0x00000001, NA, CPUID_REG_ECX, 18,  1},
        {"pdcm",         0x00000001, NA, CPUID_REG_ECX, 15,  1},
        {"xtpr",         0x00000001, NA, CPUID_REG_ECX, 14,  1},
        {"cmpxchg16",    0x00000001, NA, CPUID_REG_ECX, 13,  1},
        {"cntxid",       0x00000001, NA, CPUID_REG_ECX, 10,  1},
        {"ssse3",        0x00000001, NA, CPUID_REG_ECX,  9,  1},
        {"tm2",          0x00000001, NA, CPUID_REG_ECX,  8,  1},
        {"est",          0x00000001, NA, CPUID_REG_ECX,  7,  1},
        {"smx",          0x00000001, NA, CPUID_REG_ECX,  6,  1},
        {"vmx",          0x00000001, NA, CPUID_REG_ECX,  5,  1},
        {"dscpl",        0x00000001, NA, CPUID_REG_ECX,  4,  1},
        {"monitor",      0x00000001, NA, CPUID_REG_ECX,  3,  1},
        {"dtes64",       0x00000001, NA, CPUID_REG_ECX,  2,  1},
        {"pclmulqdq",    0x00000001, NA, CPUID_REG_ECX,  1,  1},
        {"sse3",         0x00000001, NA, CPUID_REG_ECX,  0,  1},
        {"pbe",          0x00000001, NA, CPUID_REG_EDX, 31,  1},
        {"ia64",         0x00000001, NA, CPUID_REG_EDX, 30,  1},
        {"tm",           0x00000001, NA, CPUID_REG_EDX, 29,  1},
        {"htt",          0x00000001, NA, CPUID_REG_EDX, 28,  1},
        {"ss",           0x00000001, NA, CPUID_REG_EDX, 27,  1},
        {"sse2",         0x00000001, NA, CPUID_REG_EDX, 26,  1},
        {"sse",          0x00000001, NA, CPUID_REG_EDX, 25,  1},
        {"fxsr",         0x00000001, NA, CPUID_REG_EDX, 24,  1},
        {"mmx",          0x00000001, NA, CPUID_REG_EDX, 23,  1},
        {"acpi",         0x00000001, NA, CPUID_REG_EDX, 22,  1},
        {"ds",           0x00000001, NA, CPUID_REG_EDX, 21,  1},
        {"clfsh",        0x00000001, NA, CPUID_REG_EDX, 19,  1},
        {"psn",          0x00000001, NA, CPUID_REG_EDX, 18,  1},
        {"pse36",        0x00000001, NA, CPUID_REG_EDX, 17,  1},
        {"pat",          0x00000001, NA, CPUID_REG_EDX, 16,  1},
        {"cmov",         0x00000001, NA, CPUID_REG_EDX, 15,  1},
        {"mca",          0x00000001, NA, CPUID_REG_EDX, 14,  1},
        {"pge",          0x00000001, NA, CPUID_REG_EDX, 13,  1},
        {"mtrr",         0x00000001, NA, CPUID_REG_EDX, 12,  1},
        {"sysenter",     0x00000001, NA, CPUID_REG_EDX, 11,  1},
        {"apic",         0x00000001, NA, CPUID_REG_EDX,  9,  1},
        {"cmpxchg8",     0x00000001, NA, CPUID_REG_EDX,  8,  1},
        {"mce",          0x00000001, NA, CPUID_REG_EDX,  7,  1},
        {"pae",          0x00000001, NA, CPUID_REG_EDX,  6,  1},
        {"msr",          0x00000001, NA, CPUID_REG_EDX,  5,  1},
        {"tsc",          0x00000001, NA, CPUID_REG_EDX,  4,  1},
        {"pse",          0x00000001, NA, CPUID_REG_EDX,  3,  1},
        {"de",           0x00000001, NA, CPUID_REG_EDX,  2,  1},
        {"vme",          0x00000001, NA, CPUID_REG_EDX,  1,  1},
        {"fpu",          0x00000001, NA, CPUID_REG_EDX,  0,  1},
        {"topoext",      0x80000001, NA, CPUID_REG_ECX, 22,  1},
        {"tbm",          0x80000001, NA, CPUID_REG_ECX, 21,  1},
        {"nodeid",       0x80000001, NA, CPUID_REG_ECX, 19,  1},
        {"fma4",         0x80000001, NA, CPUID_REG_ECX, 16,  1},
        {"lwp",          0x80000001, NA, CPUID_REG_ECX, 15,  1},
        {"wdt",          0x80000001, NA, CPUID_REG_ECX, 13,  1},
        {"skinit",       0x80000001, NA, CPUID_REG_ECX, 12,  1},
        {"xop",          0x80000001, NA, CPUID_REG_ECX, 11,  1},
        {"ibs",          0x80000001, NA, CPUID_REG_ECX, 10,  1},
        {"osvw",         0x80000001, NA, CPUID_REG_ECX, 10,  1},
        {"3dnowprefetch",0x80000001, NA, CPUID_REG_ECX,  8,  1},
        {"misalignsse",  0x80000001, NA, CPUID_REG_ECX,  7,  1},
        {"sse4a",        0x80000001, NA, CPUID_REG_ECX,  6,  1},
        {"abm",          0x80000001, NA, CPUID_REG_ECX,  5,  1},
        {"altmovcr8",    0x80000001, NA, CPUID_REG_ECX,  4,  1},
        {"extapic",      0x80000001, NA, CPUID_REG_ECX,  3,  1},
        {"svm",          0x80000001, NA, CPUID_REG_ECX,  2,  1},
        {"cmplegacy",    0x80000001, NA, CPUID_REG_ECX,  1,  1},
        {"lahfsahf",     0x80000001, NA, CPUID_REG_ECX,  0,  1},
        {"3dnow",        0x80000001, NA, CPUID_REG_EDX, 31,  1},
        {"3dnowext",     0x80000001, NA, CPUID_REG_EDX, 30,  1},
        {"lm",           0x80000001, NA, CPUID_REG_EDX, 29,  1},
        {"rdtscp",       0x80000001, NA, CPUID_REG_EDX, 27,  1},
        {"page1gb",      0x80000001, NA, CPUID_REG_EDX, 26,  1},
        {"ffxsr",        0x80000001, NA, CPUID_REG_EDX, 25,  1},
        {"mmxext",       0x80000001, NA, CPUID_REG_EDX, 22,  1},
        {"nx",           0x80000001, NA, CPUID_REG_EDX, 20,  1},
        {"syscall",      0x80000001, NA, CPUID_REG_EDX, 11,  1},
        {"procpkg",      0x00000004,  0, CPUID_REG_EAX, 26,  6},
        {"apicidsize",   0x80000008, NA, CPUID_REG_ECX, 12,  4},
        {"nc",           0x80000008, NA, CPUID_REG_ECX,  0,  8},

        {NULL, 0, CPUID_REG_INV, 0, 0}
    };
#undef NA
    char *sep, *val, *endptr;
    int i;
    struct cpuid_flags *flag;
    struct libxl__cpuid_policy *entry;
    unsigned long num;
    char flags[33], *resstr;

    sep = strchr(str, '=');
    if (sep == NULL) {
        return 1;
    } else {
        val = sep + 1;
    }
    for (flag = cpuid_flags; flag->name != NULL; flag++) {
        if(!strncmp(str, flag->name, sep - str) && flag->name[sep - str] == 0)
            break;
    }
    if (flag->name == NULL) {
        return 2;
    }
    entry = cpuid_find_match(cpuid, flag->leaf, flag->subleaf);
    resstr = entry->policy[flag->reg - 1];
    if (resstr == NULL) {
        resstr = strdup("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }
    num = strtoull(val, &endptr, 0);
    flags[flag->length] = 0;
    if (endptr != val) {
        /* is this was a valid number, write the binary form into the string */
        for (i = 0; i < flag->length; i++) {
            flags[flag->length - 1 - i] = "01"[!!(num & (1 << i))];
        }
    } else {
        switch(val[0]) {
        case 'x': case 'k': case 's':
            memset(flags, val[0], flag->length);
            break;
        default:
            return 3;
        }
    }
    /* the family and model entry is potentially split up across
     * two fields in Fn0000_0001_EAX, so handle them here separately.
     */
    if (!strncmp(str, "family", sep - str)) {
        if (num < 16) {
            memcpy(resstr + (32 - 4) - flag->bit, flags + 4, 4);
            memcpy(resstr + (32 - 8) - 20, "00000000", 8);
        } else {
            num -= 15;
            memcpy(resstr + (32 - 4) - flag->bit, "1111", 4);
            for (i = 0; i < 7; i++) {
                flags[7 - i] = "01"[num & 1];
                num >>= 1;
            }
            memcpy(resstr + (32 - 8) - 20, flags, 8);
        }
    } else if (!strncmp(str, "model", sep - str)) {
        memcpy(resstr + (32 - 4) - 16, flags, 4);
        memcpy(resstr + (32 - 4) - flag->bit, flags + 4, 4);
    } else {
        memcpy(resstr + (32 - flag->length) - flag->bit, flags,
               flag->length);
    }
    entry->policy[flag->reg - 1] = resstr;

    return 0;
}

/* parse a single list item from the legacy Python xend syntax, where
 * the strings for each register were directly exposed to the user.
 * Used for maintaining compatibility with older config files
 */
int libxl_cpuid_parse_config_xend(libxl_cpuid_policy_list *cpuid,
                                  const char* str)
{
    char *endptr;
    unsigned long value;
    uint32_t leaf, subleaf = XEN_CPUID_INPUT_UNUSED;
    struct libxl__cpuid_policy *entry;

    /* parse the leaf number */
    value = strtoul(str, &endptr, 0);
    if (str == endptr) {
        return 1;
    }
    leaf = value;
    /* check for an optional subleaf number */
    if (*endptr == ',') {
        str = endptr + 1;
        value = strtoul(str, &endptr, 0);
        if (str == endptr) {
            return 2;
        }
        subleaf = value;
    }
    if (*endptr != ':') {
        return 3;
    }
    str = endptr + 1;
    entry = cpuid_find_match(cpuid, leaf, subleaf);
    for (str = endptr + 1; *str != 0;) {
        if (str[0] != 'e' || str[2] != 'x') {
            return 4;
        }
        value = str[1] - 'a';
        endptr = strchr(str, '=');
        if (value < 0 || value > 3 || endptr == NULL) {
            return 4;
        }
        str = endptr + 1;
        endptr = strchr(str, ',');
        if (endptr == NULL) {
            endptr = strchr(str, 0);
        }
        if (endptr - str != 32) {
            return 5;
        }
        entry->policy[value] = calloc(32 + 1, 1);
        strncpy(entry->policy[value], str, 32);
        entry->policy[value][32] = 0;
        if (*endptr == 0) {
            break;
        }
        for (str = endptr + 1; *str == ' ' || *str == '\n'; str++);
    }
    return 0;
}

void libxl_cpuid_apply_policy(libxl_ctx *ctx, uint32_t domid)
{
    xc_cpuid_apply_policy(ctx->xch, domid);
}

void libxl_cpuid_set(libxl_ctx *ctx, uint32_t domid,
		     libxl_cpuid_policy_list cpuid)
{
    int i;
    char *cpuid_res[4];

    for (i = 0; cpuid[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++)
        xc_cpuid_set(ctx->xch, domid, cpuid[i].input,
                     (const char**)(cpuid[i].policy), cpuid_res);
}
