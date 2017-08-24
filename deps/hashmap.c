/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hashmap.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef struct entry_s entry_t;
struct entry_s
{
    const void* key;
    int hash;
    void* value;
    entry_t* next;
};

struct hashmap_s
{
    entry_t** buckets;
    size_t bucketCount;
    int (*hash)(const void* key);
    int (*equals)(const void* keyA, const void* keyB);
    size_t size;
};

static int string_hash(const void* key) {
    return hm_hash(key, strlen(key));
}
static int string_equals(const void* keyA, const void* keyB) {
    return strcmp(keyA, keyB) == 0;
}

hashmap_t* hm_alloc(size_t initialCapacity,
        int (*hash)(const void* key),
        int (*equals)(const void* keyA, const void* keyB)) {

    if (!hash)
        hash = string_hash;

    if (!equals)
        equals = string_equals;
    
    hashmap_t* map = malloc(sizeof(hashmap_t));
    if (map == NULL) {
        return NULL;
    }
    
    // 0.75 load factor.
    size_t minimumBucketCount = initialCapacity * 4 / 3;
    map->bucketCount = 1;
    while (map->bucketCount <= minimumBucketCount) {
        // Bucket count must be power of 2.
        map->bucketCount <<= 1; 
    }

    map->buckets = calloc(map->bucketCount, sizeof(entry_t*));
    if (map->buckets == NULL) {
        free(map);
        return NULL;
    }
    
    map->size = 0;

    map->hash = hash;
    map->equals = equals;

    return map;
}

/**
 * Hashes the given key.
 */
static inline int hash_key(hashmap_t* map, const void* key) {
    int h = map->hash(key);

    // We apply this secondary hashing discovered by Doug Lea to defend
    // against bad hashes.
    h += ~(h << 9);
    h ^= (((unsigned int) h) >> 14);
    h += (h << 4);
    h ^= (((unsigned int) h) >> 10);
       
    return h;
}

size_t hm_size(hashmap_t* map) {
    return map->size;
}

static inline size_t calculate_index(size_t bucketCount, int hash) {
    return ((size_t) hash) & (bucketCount - 1);
}

static void expand_if_necessary(hashmap_t* map) {
    // If the load factor exceeds 0.75...
    if (map->size > (map->bucketCount * 3 / 4)) {
        // Start off with a 0.33 load factor.
        size_t newBucketCount = map->bucketCount << 1;
        entry_t** newBuckets = calloc(newBucketCount, sizeof(entry_t*));
        if (newBuckets == NULL) {
            // Abort expansion.
            return;
        }
        
        // Move over existing entries.
        size_t i;
        for (i = 0; i < map->bucketCount; i++) {
            entry_t* entry = map->buckets[i];
            while (entry != NULL) {
                entry_t* next = entry->next;
                size_t index = calculate_index(newBucketCount, entry->hash);
                entry->next = newBuckets[index];
                newBuckets[index] = entry;
                entry = next;
            }
        }

        // Copy over internals.
        free(map->buckets);
        map->buckets = newBuckets;
        map->bucketCount = newBucketCount;
    }
}

void hm_free(hashmap_t* map) {
    if (!map)
        return;
    size_t i;
    for (i = 0; i < map->bucketCount; i++) {
        entry_t* entry = map->buckets[i];
        while (entry != NULL) {
            entry_t* next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(map->buckets);
    free(map);
}

int hm_hash(const void* key, size_t keySize) {
    int h = keySize;
    char* data = (char*) key;
    size_t i;
    for (i = 0; i < keySize; i++) {
        h = h * 31 + *data;
        data++;
    }
    return h;
}

static entry_t* create_entry(const void* key, int hash, void* value) {
    entry_t* entry = malloc(sizeof(entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = key;
    entry->hash = hash;
    entry->value = value;
    entry->next = NULL;
    return entry;
}

static inline int equal_keys(
        const void* keyA, int hashA, const void* keyB, int hashB,
        int (*equals)(const void*, const void*)) {
    if (keyA == keyB) {
        return 1;
    }
    if (hashA != hashB) {
        return 0;
    }
    return equals(keyA, keyB);
}

void* hm_put(hashmap_t* map, const void* key, void* value) {
    int hash = hash_key(map, key);
    size_t index = calculate_index(map->bucketCount, hash);

    entry_t** p = &(map->buckets[index]);
    while (1) {
        entry_t* current = *p;

        // Add a new entry.
        if (current == NULL) {
            *p = create_entry(key, hash, value);
            if (*p == NULL) {
                errno = ENOMEM;
                return NULL;
            }
            map->size++;
            expand_if_necessary(map);
            return NULL;
        }

        // Replace existing entry.
        if (equal_keys(current->key, current->hash, key, hash, map->equals)) {
            void* oldValue = current->value;
            current->value = value;
            return oldValue;
        }

        // Move to next entry.
        p = &current->next;
    }
}

void* hm_get(hashmap_t* map, const void* key) {
    int hash = hash_key(map, key);
    size_t index = calculate_index(map->bucketCount, hash);

    entry_t* entry = map->buckets[index];
    while (entry != NULL) {
        if (equal_keys(entry->key, entry->hash, key, hash, map->equals)) {
            return entry->value;
        }
        entry = entry->next;
    }

    return NULL;
}

int hm_contains(hashmap_t* map, const void* key) {
    int hash = hash_key(map, key);
    size_t index = calculate_index(map->bucketCount, hash);

    entry_t* entry = map->buckets[index];
    while (entry != NULL) {
        if (equal_keys(entry->key, entry->hash, key, hash, map->equals)) {
            return 1;
        }
        entry = entry->next;
    }

    return 0;
}

void* hm_memoize(hashmap_t* map, const void* key,
        void* (*initialValue)(const void* key, void* context), void* context) {
    int hash = hash_key(map, key);
    size_t index = calculate_index(map->bucketCount, hash);

    entry_t** p = &(map->buckets[index]);
    while (1) {
        entry_t* current = *p;

        // Add a new entry.
        if (current == NULL) {
            *p = create_entry(key, hash, NULL);
            if (*p == NULL) {
                errno = ENOMEM;
                return NULL;
            }
            void* value = initialValue(key, context);
            (*p)->value = value;
            map->size++;
            expand_if_necessary(map);
            return value;
        }

        // Return existing value.
        if (equal_keys(current->key, current->hash, key, hash, map->equals)) {
            return current->value;
        }

        // Move to next entry.
        p = &current->next;
    }

    return NULL;
}

void* hm_remove(hashmap_t* map, const void* key) {
    if (!map)
        return NULL;
    int hash = hash_key(map, key);
    size_t index = calculate_index(map->bucketCount, hash);

    // Pointer to the current entry.
    entry_t** p = &(map->buckets[index]);
    entry_t* current;
    while ((current = *p) != NULL) {
        if (equal_keys(current->key, current->hash, key, hash, map->equals)) {
            void* value = current->value;
            *p = current->next;
            free(current);
            map->size--;
            return value;
        }

        p = &current->next;
    }

    return NULL;
}

int hm_foreach(hashmap_t* map,
        int (*callback)(const void* key, void* value, void* context),
        void* context) {
    if (!map)
        return 0;
    size_t i;
    for (i = 0; i < map->bucketCount; i++) {
        entry_t* entry = map->buckets[i];
        while (entry != NULL) {
            entry_t *next = entry->next;
            if (!callback(entry->key, entry->value, context)) {
                return 0;
            }
            entry = next;
        }
    }
    return 1;
}

size_t hm_current_capacity(hashmap_t* map) {
    size_t bucketCount = map->bucketCount;
    return bucketCount * 3 / 4;
}

size_t hm_count_collisions(hashmap_t* map) {
    size_t collisions = 0;
    size_t i;
    for (i = 0; i < map->bucketCount; i++) {
        entry_t* entry = map->buckets[i];
        while (entry != NULL) {
            if (entry->next != NULL) {
                collisions++;
            }
            entry = entry->next;
        }
    }
    return collisions;
}

int hm_int_hash(const void* key) {
    // Return the key value itself.
    return *((int*) key);
}

int hm_int_equals(const void* keyA, const void* keyB) {
    int a = *((int*) keyA);
    int b = *((int*) keyB);
    return a == b;
}
