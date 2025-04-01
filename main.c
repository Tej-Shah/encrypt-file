#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUFFER_SIZE 1024
#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32 // AES-256 key size

// Simple XOR Encrypt/Decrypt function
void xor_encrypt_decrypt_buffer(unsigned char *buffer, size_t length, const char *key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < length; i++) {
        buffer[i] ^= key[i % key_len]; // XOR with key
    }
}

// AES S-Box for SubBytes transformation (Placeholder, full implementation needed)
static const uint8_t sbox[256] = { /* Full AES S-Box table required */ };

// Simple AES Key Expansion stub (requires full AES implementation)
void aes_key_expansion(const uint8_t *key, uint8_t *expandedKeys) {
    // Key expansion logic here (omitted for brevity)
}

// AES Encryption function (Placeholder, assumes 1-block encryption)
void aes_encrypt_block(uint8_t *block, const uint8_t *roundKeys) {
    // AES encryption steps (Placeholder)
}

// AES Decryption function (Placeholder, assumes 1-block decryption)
void aes_decrypt_block(uint8_t *block, const uint8_t *roundKeys) {
    // AES decryption steps (Placeholder)
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
