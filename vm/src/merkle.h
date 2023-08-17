#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "cx.h"

struct proof_s {
    uint8_t op;
    uint8_t digest[32];
} __attribute__((packed));

/*
 * Merkle Tree node.
 */
struct entry_s {
    union {
        uint8_t data[8];
        struct {
            uint32_t addr;
            uint32_t iv;
        };
    };
} __attribute__((packed));

struct merkle_tree_ctx_s {
    uint8_t root_hash[CX_SHA256_SIZE];
    size_t n;
    struct entry_s last_entry;
};

bool merkle_insert(const struct entry_s *entry, const struct proof_s *proof, size_t count);
bool merkle_update(const struct entry_s *old_entry,
                   const struct entry_s *entry,
                   const struct proof_s *proof,
                   size_t count);
bool merkle_verify_proof(const struct entry_s *entry, const struct proof_s *proof, size_t count);
void init_merkle_tree(const uint8_t *root_hash_init,
                      size_t merkle_tree_size,
                      const struct entry_s *last_entry_init);


// Computes the hash of an entry (leaf)
void init_digest(uint8_t digest[static CX_SHA256_SIZE], const struct entry_s *entry);

// Given a number of elements of a Merkle proof, computes the hash of the internal node obtained
// by processing the proof element. If the proof is complete, then it's the Merkle root.
// Return -1 if proof_bytes_len is not a multiple of sizeof(struct proof_s), otherwise returns
// the number of proof elements processed: proof_bytes_len / sizeof(struct proof_s).
int update_with_partial_proof(uint8_t digest[static CX_SHA256_SIZE], uint8_t *proof_bytes, size_t proof_bytes_len);

// Given a digest, checks if it matches the current Merkle root.
bool compare_merkle_root_with_digest(uint8_t digest[static CX_SHA256_SIZE])