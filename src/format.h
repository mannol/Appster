#ifndef FORMAT_H
#define FORMAT_H

#include <stdint.h>

#define base64_encoded_len(n) (((4 * n / 3) + 3) & ~3)
uint32_t base64_decoded_len(const char *base64, uint32_t len);

uint32_t from_base64 (const char *str, char* output);
const char* to_base64(const char* str);
const char* to_base64_ex(const char* str, uint32_t len);
int urldecode(const char* src, char* dst);

#endif /* FORMAT_H */
