#pragma once
#include <stdint.h>

unsigned char* ReadFileToBuffer(const char* filename, size_t* out_size);
unsigned char* ExtractBlob(const char* carrier_file, size_t* out_size);
unsigned char* DecryptBlob(const unsigned char* blob, size_t blob_size, size_t* out_size);
unsigned char* Decrypt(const char* carrier_file, size_t* out_size);

