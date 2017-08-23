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

/**
 * Hash map.
 */

#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** A hash map. */
typedef struct hashmap_s hashmap_t;

/**
 * Creates a new hash map. Returns NULL if memory allocation fails.
 *
 * @param initialCapacity number of expected entries
 * @param hash function which hashes keys
 * @param equals function which compares keys for equality
 */
hashmap_t* hm_alloc(size_t initialCapacity,
        int (*hash)(const void* key), int (*equals)(const void* keyA, const void* keyB));

/**
 * Frees the hash map. Does not free the keys or values themselves.
 */
void hm_free(hashmap_t* map);

/**
 * Hashes the memory pointed to by key with the given size. Useful for
 * implementing hash functions.
 */
int hm_hash(const void* key, size_t keySize);

/**
 * Puts value for the given key in the map. Returns pre-existing value if
 * any.
 *
 * If memory allocation fails, this function returns NULL, the map's size
 * does not increase, and errno is set to ENOMEM.
 */
void* hm_put(hashmap_t* map, const void* key, void* value);

/**
 * Gets a value from the map. Returns NULL if no entry for the given key is
 * found or if the value itself is NULL.
 */
void* hm_get(hashmap_t* map, const void* key);

/**
 * Returns true if the map contains an entry for the given key.
 */
int hm_contains(hashmap_t* map, const void* key);

/**
 * Gets the value for a key. If a value is not found, this function gets a 
 * value and creates an entry using the given callback.
 *
 * If memory allocation fails, the callback is not called, this function
 * returns NULL, and errno is set to ENOMEM.
 */
void* hm_memoize(hashmap_t* map, const void* key,
        void* (*initialValue)(const void* key, void* context), void* context);

/**
 * Removes an entry from the map. Returns the removed value or NULL if no
 * entry was present.
 */
void* hm_remove(hashmap_t* map, const void* key);

/**
 * Gets the number of entries in this map.
 */
size_t hm_size(hashmap_t* map);

/**
 * Invokes the given callback on each entry in the map. Stops iterating if
 * the callback returns false. Returns false if interrupted by the callback, or
 * true if iteration completed.
 */
int hm_foreach(hashmap_t* map,
        int (*callback)(const void* key, void* value, void* context),
        void* context);


/**
 * Key utilities.
 */

/**
 * Hashes int keys. 'key' is a pointer to int.
 */
int hm_int_hash(const void* key);

/**
 * Compares two int keys for equality.
 */
int hm_int_equals(const void* keyA, const void* keyB);

/**
 * For debugging.
 */

/**
 * Gets current capacity.
 */
size_t hm_current_capacity(hashmap_t* map);

/**
 * Counts the number of entry collisions.
 */
size_t hm_count_collisions(hashmap_t* map);

#ifdef __cplusplus
}
#endif

#endif /* HASHMAP_H */
