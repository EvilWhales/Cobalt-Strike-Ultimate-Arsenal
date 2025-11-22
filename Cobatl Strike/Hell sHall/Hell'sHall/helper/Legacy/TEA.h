#ifndef TEA_DECRYPT_BE_H
#define TEA_DECRYPT_BE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

// TEA constants
#define TEA_DELTA 0x9E3779B9
#define TEA_ROUNDS 32
#define TEA_BLOCK_SIZE 8
#define TEA_KEY_SIZE   16

// --- Helper: read/write big-endian 32-bit words ---
static inline uint32_t read_be32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) |
        ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) |
        ((uint32_t)p[3]);
}

static inline void write_be32(unsigned char* p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

// --- TEA decryption for one block (big-endian) ---
static inline void TEA_decrypt_block_be(const unsigned char in[8],
    unsigned char out[8],
    const uint32_t k[4]) {
    uint32_t v0 = read_be32(in);
    uint32_t v1 = read_be32(in + 4);
    uint32_t sum = (TEA_DELTA * TEA_ROUNDS) & 0xFFFFFFFF;

    for (int i = 0; i < TEA_ROUNDS; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v1 &= 0xFFFFFFFF;
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v0 &= 0xFFFFFFFF;
        sum -= TEA_DELTA;
        sum &= 0xFFFFFFFF;
    }

    write_be32(out, v0);
    write_be32(out + 4, v1);
}

// --- Convert raw key bytes (big-endian like Python) ---
static inline void prepareKey_be(const unsigned char* keyBytes, uint32_t k[4]) {
    for (int i = 0; i < 4; i++) {
        k[i] = read_be32(keyBytes + (i * 4));
    }
}

// --- ECB-mode decryption ---
static inline unsigned char* DecryptPayload(const unsigned char* payload,
    size_t length,
    const unsigned char* keyBytes) {
    if (length % TEA_BLOCK_SIZE != 0) {
        //printf("[-] Payload length must be multiple of 8 bytes!\n");
        return NULL;
    }

    unsigned char* out = (unsigned char*)malloc(length);
    if (!out) return NULL;

    uint32_t key[4];
    prepareKey_be(keyBytes, key);

    for (size_t i = 0; i < length; i += TEA_BLOCK_SIZE) {
        TEA_decrypt_block_be(payload + i, out + i, key);
    }

    return out;
}

void PrintHexBuffer(const unsigned char* buffer, SIZE_T size) {
    if (!buffer || size == 0) {
        //printf("[!] Empty buffer\n");
        return;
    }

    for (SIZE_T i = 0; i < size; i++) {
        // Print each byte as two hex characters
        printf("0x%02X ", buffer[i]);

        // Optional: newline every 16 bytes for readability
        if ((i + 1) % 16 == 0)
            printf("\n\t\t");
    }
    printf("\n");
}

#endif // TEA_DECRYPT_H
#pragma once
