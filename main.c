#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUFFER_SIZE 1024
#define AES_BLOCK_SIZE 16
#define AES_BLOCK_SIZE 16 // AES block size is 128 bits
#define ROUNDS 10 // For AES-256 (rounds = 14, key size = 256 bits)
#define KEY_SIZE 32 // AES-256 key size

// Simple XOR Encrypt/Decrypt function
void xor_encrypt_decrypt_buffer(unsigned char *buffer, size_t length, const char *key)
{
    size_t key_len;

    key_len = strlen(key);
    for (size_t i = 0; i < length; i++)
    {
        buffer[i] ^= key[i % key_len]; // XOR with key
    }
}

// AES S-Box for SubBytes transformation (Placeholder, full implementation needed)
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


// Simple AES Key Expansion stub (requires full AES implementation)
void aes_key_expansion(const uint8_t *key, uint8_t *expandedKeys) {
    // Key expansion logic here (omitted for brevity)
}

// Rotate the 32-bit word left by 8 bits
uint32_t rot_word(uint32_t word) {
    return (word << 8) | (word >> 24);
}

// Apply the S-Box substitution to a word
uint32_t sub_word(uint32_t word) {
    return ((uint32_t)sbox[(word >> 24) & 0xFF] << 24) |
           ((uint32_t)sbox[(word >> 16) & 0xFF] << 16) |
           ((uint32_t)sbox[(word >> 8) & 0xFF] << 8) |
           ((uint32_t)sbox[word & 0xFF]);
}

// Perform AES AddRoundKey step
void add_round_key(uint8_t *block, const uint8_t *roundKey) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        block[i] ^= roundKey[i];
    }
}

// Perform the SubBytes step
void sub_bytes(uint8_t *block) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        block[i] = sbox[block[i]];
    }
}

// Perform the ShiftRows step
void shift_rows(uint8_t *block) {
    uint8_t temp[AES_BLOCK_SIZE];

    // Shift rows
    temp[0] = block[0]; temp[1] = block[1]; temp[2] = block[2]; temp[3] = block[3];
    temp[4] = block[5]; temp[5] = block[6]; temp[6] = block[7]; temp[7] = block[4];
    temp[8] = block[10]; temp[9] = block[11]; temp[10] = block[8]; temp[11] = block[9];
    temp[12] = block[15]; temp[13] = block[12]; temp[14] = block[13]; temp[15] = block[14];

    // Copy back to block
    memcpy(block, temp, AES_BLOCK_SIZE);
}

// Perform the MixColumns step
void mix_columns(uint8_t *block) {
    for (int i = 0; i < 4; i++) {
        uint8_t col[4];
        for (int j = 0; j < 4; j++) {
            col[j] = block[i + j * 4];
        }

        // Mix columns logic (needs proper implementation for Galois Field multiplication)
        // Placeholder for MixColumns transformation, you should implement matrix multiplication in GF(2^8)
    }
}

// AES encryption for 1 block
void aes_encrypt_block(uint8_t *block, const uint8_t *roundKeys) {
    // Initial AddRoundKey step
    add_round_key(block, roundKeys);

    // Main rounds (9 rounds)
    for (int round = 1; round < ROUNDS; round++) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &roundKeys[round * AES_BLOCK_SIZE]);
    }

    // Final round (no MixColumns)
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &roundKeys[ROUNDS * AES_BLOCK_SIZE]);
}

// Multiply by 0x0e (Galois Field multiplication for the inverse of MixColumns)
uint8_t gf_multiply_inv(uint8_t a) {
    uint8_t result = a;
    if (a == 0) return 0;  // If a is 0, return 0
    for (int i = 0; i < 7; i++) {
        result = (result << 1) ^ ((result & 0x80) ? 0x1b : 0); // Shift left and reduce mod x^8 + x^4 + x^3 + x + 1
    }
    return result;
}

// Inverse ShiftRows operation
void inv_shift_rows(uint8_t *block) {
    uint8_t temp[16];
    memcpy(temp, block, 16);

    // Perform the inverse of the ShiftRows step (shift rows to the right)
    temp[1] = block[5];
    temp[5] = block[9];
    temp[9] = block[13];
    temp[13] = block[1];

    temp[2] = block[10];
    temp[6] = block[14];
    temp[10] = block[2];
    temp[14] = block[6];

    temp[3] = block[15];
    temp[7] = block[3];
    temp[11] = block[7];
    temp[15] = block[11];

    memcpy(block, temp, 16);
}

// Inverse MixColumns operation (for decryption)
void inv_mix_columns(uint8_t *block) {
    for (int col = 0; col < 4; col++) {
        uint8_t a = block[col];
        uint8_t b = block[col + 4];
        uint8_t c = block[col + 8];
        uint8_t d = block[col + 12];

        // Apply the inverse MixColumns matrix multiplication (using the Galois Field)
        block[col] = gf_multiply_inv(a) ^ gf_multiply_inv(b) ^ c ^ d;
        block[col + 4] = a ^ gf_multiply_inv(b) ^ gf_multiply_inv(c) ^ d;
        block[col + 8] = a ^ b ^ gf_multiply_inv(c) ^ gf_multiply_inv(d);
        block[col + 12] = gf_multiply_inv(a) ^ b ^ c ^ gf_multiply_inv(d);
    }
}

// AES Decryption for 1 block
void aes_decrypt_block(uint8_t *block, const uint8_t *roundKeys) {
    // Initial AddRoundKey
    add_round_key(block, roundKeys + 10 * AES_BLOCK_SIZE);  // 10th round key for AES-128 (final round)

    // 9 rounds of decryption
    for (int round = 9; round >= 1; round--) {
        inv_sub_bytes(block);           // Inverse of SubBytes
        inv_shift_rows(block);         // Inverse of ShiftRows
        inv_mix_columns(block);        // Inverse of MixColumns
        add_round_key(block, roundKeys + round * AES_BLOCK_SIZE); // Apply the round key
    }

    // Final round (no InvMixColumns)
    inv_sub_bytes(block);
    inv_shift_rows(block);
    add_round_key(block, roundKeys);  // First round key (same as in encryption)
}

// Combined AES + XOR File Encryption
void encrypt_file(const char *input_filename, const char *output_filename, const uint8_t *aes_key, const char *xor_key) {
    FILE *infile = fopen(input_filename, "rb");
    FILE *outfile = fopen(output_filename, "wb");
    if (!infile || !outfile) {
        perror("File opening failed");
        exit(1);
    }
    
    uint8_t expandedKeys[240]; // Key expansion storage
    aes_key_expansion(aes_key, expandedKeys);
    
    unsigned char buffer[AES_BLOCK_SIZE];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, infile)) > 0) {
        if (bytes_read < AES_BLOCK_SIZE) {
            memset(buffer + bytes_read, AES_BLOCK_SIZE - bytes_read, AES_BLOCK_SIZE - bytes_read); // PKCS7 padding
        }
        
        xor_encrypt_decrypt_buffer(buffer, AES_BLOCK_SIZE, xor_key);
        aes_encrypt_block(buffer, expandedKeys);
        
        fwrite(buffer, 1, AES_BLOCK_SIZE, outfile);
    }
    
    fclose(infile);
    fclose(outfile);
    printf("AES + XOR encryption completed: %s\n", output_filename);
}

// Combined AES + XOR File Decryption
void decrypt_file(const char *input_filename, const char *output_filename, const uint8_t *aes_key, const char *xor_key) {
    FILE *infile = fopen(input_filename, "rb");
    FILE *outfile = fopen(output_filename, "wb");
    if (!infile || !outfile) {
        perror("File opening failed");
        exit(1);
    }
    
    uint8_t expandedKeys[240]; // Key expansion storage
    aes_key_expansion(aes_key, expandedKeys);
    
    unsigned char buffer[AES_BLOCK_SIZE];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, infile)) > 0) {
        aes_decrypt_block(buffer, expandedKeys);
        xor_encrypt_decrypt_buffer(buffer, AES_BLOCK_SIZE, xor_key);
        
        fwrite(buffer, 1, AES_BLOCK_SIZE, outfile);
    }
    
    fclose(infile);
    fclose(outfile);
    printf("AES + XOR decryption completed: %s\n", output_filename);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <encrypt|decrypt> <input_file> <output_file> <aes_key> <xor_key>\n", argv[0]);
        return 1;
    }
    
    const char *operation = argv[1];
    const char *input_file = argv[2];
    const char *output_file = argv[3];
    
    uint8_t aes_key[KEY_SIZE];
    strncpy((char *)aes_key, argv[4], KEY_SIZE);
    
    if (strcmp(operation, "encrypt") == 0) {
        encrypt_file(input_file, output_file, aes_key, argv[5]);
    } else if (strcmp(operation, "decrypt") == 0) {
        decrypt_file(input_file, output_file, aes_key, argv[5]);
    } else {
        printf("Invalid operation. Use 'encrypt' or 'decrypt'.\n");
        return 1;
    }
    
    return 0;
}
