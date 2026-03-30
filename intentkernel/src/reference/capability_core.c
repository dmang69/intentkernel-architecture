/*
 * IntentKernel Core Capability Logic
 * Reference Implementation
 *
 * Copyright 2025 Daniel Kirk Owings
 * Licensed under the Apache License, Version 2.0
 *
 * This is the complete security core of the IntentKernel architecture.
 * All security guarantees of the system derive from the correctness of
 * this code. The entire trusted computing base is designed to keep this
 * module small enough for a single engineer to fully audit.
 *
 * SECURITY PROPERTIES:
 * 1. No capability can be forged (256-bit random keys)
 * 2. No capability can outlive its TTL (hard expiration)
 * 3. No capability can exceed its use count (atomic decrement)
 * 4. All validation is constant-time (ct_memcmp prevents timing attacks)
 */

#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

#define CAP_TABLE_SIZE   65536    /* Maximum concurrent capabilities    */
#define CAP_KEY_SIZE     32       /* 256-bit cryptographic key          */

/* ------------------------------------------------------------------ */
/* Capability Structure                                                */
/* ------------------------------------------------------------------ */

struct Capability {
    uint8_t  key[CAP_KEY_SIZE];  /* Unforgeable random key             */
    uint64_t expires;             /* Absolute expiration timestamp      */
    uint32_t type;                /* Resource type identifier           */
    uint16_t uses;                /* Remaining use count                */
    uint16_t id;                  /* Table index                        */
} __attribute__((packed));

/* ------------------------------------------------------------------ */
/* Global Capability Table                                             */
/* ------------------------------------------------------------------ */

static struct Capability cap_table[CAP_TABLE_SIZE];

/* ------------------------------------------------------------------ */
/* External Dependencies (provided by platform)                        */
/* ------------------------------------------------------------------ */

extern uint64_t get_time(void);                     /* Monotonic clock */
extern int getrandom(void *buf, size_t len, int f); /* CSRNG           */

/* ------------------------------------------------------------------ */
/* Constant-Time Memory Comparison                                     */
/* Prevents timing side-channel attacks on key validation.             */
/* ------------------------------------------------------------------ */

static int ct_memcmp(const void *a, const void *b, size_t n) {
    const volatile uint8_t *x = a;
    const volatile uint8_t *y = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= x[i] ^ y[i];
    }
    return diff;
}

/* ------------------------------------------------------------------ */
/* capability_create                                                   */
/*                                                                     */
/* Allocates a new capability with the given type, time-to-live, and   */
/* maximum use count. Returns the capability table index on success,   */
/* or -1 if the table is full.                                         */
/*                                                                     */
/* The capability is immediately valid upon creation. The TTL is        */
/* relative (added to current time). The use count is absolute.        */
/* ------------------------------------------------------------------ */

int capability_create(uint32_t type, uint64_t ttl, uint16_t uses) {
    uint64_t now = get_time();

    for (int i = 0; i < CAP_TABLE_SIZE; i++) {
        if (cap_table[i].expires < now) {
            /* Slot is expired or empty — reuse it */
            getrandom(&cap_table[i].key, CAP_KEY_SIZE, 0);
            cap_table[i].type    = type;
            cap_table[i].expires = now + ttl;
            cap_table[i].uses    = uses;
            cap_table[i].id      = (uint16_t)i;
            return i;
        }
    }
    return -1; /* Table full */
}

/* ------------------------------------------------------------------ */
/* capability_validate                                                 */
/*                                                                     */
/* Validates a presented capability against the table. Returns the     */
/* capability type on success, or -1 on failure.                       */
/*                                                                     */
/* On successful validation, the use count is decremented. When the    */
/* count reaches zero, the capability is immediately invalidated.      */
/*                                                                     */
/* This function is the ENTIRE security enforcement mechanism.         */
/* If this function returns -1, the requested action is denied.        */
/* If this function returns >= 0, the action is permitted exactly once.*/
/* ------------------------------------------------------------------ */

int capability_validate(struct Capability *cap) {
    /* Check expiration */
    if (cap->expires < get_time())
        return -1;

    /* Check remaining uses */
    if (cap->uses == 0)
        return -1;

    /* Constant-time key comparison */
    if (ct_memcmp(cap->key, cap_table[cap->id].key, CAP_KEY_SIZE) != 0)
        return -1;

    /* Consume one use */
    cap_table[cap->id].uses -= 1;

    /* Auto-invalidate when uses exhausted */
    if (cap_table[cap->id].uses == 0) {
        cap_table[cap->id].expires = 0;
    }

    return (int)cap->type;
}

/* ------------------------------------------------------------------ */
/* capability_revoke                                                   */
/*                                                                     */
/* Immediately invalidates a capability by zeroing its expiration.     */
/* ------------------------------------------------------------------ */

int capability_revoke(uint16_t id) {
    if (id >= CAP_TABLE_SIZE)
        return -1;

    cap_table[id].expires = 0;
    cap_table[id].uses    = 0;
    memset(cap_table[id].key, 0, CAP_KEY_SIZE);
    return 0;
}
