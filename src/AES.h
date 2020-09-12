#pragma once

/* 
    This is a C++ implementation of the AES (Advanced Encryption Standard), based on the Rinjdael block cipher algorithm.
    Official specification can be found here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
*/

#include <stdint.h>
#include <string>
#include <cstddef>

// number of columns in one block.
#define Nb 4
// number of lines in one block (not actually part of the specification).
#define Nl 4

// AES block size in bytes
#define AES_BLOCK_SIZE 16

using namespace std;

// Possible key sizes for the AES constructor.
enum AESKeySize {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256
};

// Possible block cipher modes of operation for this implementation
enum AESMode { ECB = 0, CBC = 1 };

class AES {

    public:

    // The AES constructors.

    // The "keySize" parameter is a choice between the three AES key sizes.
    // The "mode" parameter is the block cipher mode of operation to use (see AESMode enum for all modes available).
    // The "key" parameter is the key to use for this instance of AES. Must not be NULL and must point to a buffer with a size in bits >= "keySize".
    // The "iv" parameter is the initialization vector (IV) to use for modes such as CBC. It can be NULL if the "mode" parameter indicates a mode of operation that does not require the use of an IV
    AES(AESKeySize keySize, AESMode mode, uint8_t *key, uint8_t *iv);
    
    // This constructor does not have the "iv" parameter, it could be used for modes that don't require the use of an IV.
    AES(AESKeySize keySize, AESMode mode, uint8_t *key);
    ~AES();

    /* 
        Encrypts a blob of data using AES.
        
        The "buffer" parameter is a pointer to the buffer which is to be encrypted. 
        Its content will be overwritten with the resulting encrypted buffer.
        
        PKCS#7 padding is REQUIRED. Which means you need to pad your buffer with N bytes with the value of N, where N is the length of the buffer in bytes modulo the AES cipher block size (16).
        
        Check these examples for better understanding:

        If you have a 13 byte buffer (which is NOT a multiple of th AES block size, i.e 16 bytes), you need to pad with 3 more bytes:

        00 01 02 03 04 05 06 07 08 09 0A 0B 0C = 13 bytes
        -------------- original data ---------

        becomes...

        00   01   02   03   04   05   06   07   08   09   0A   0B   0C   03     03    03 = 16 bytes
        ------------------------- original data ----------------------   --- padding ---
        
        If you have a 16 bytes buffer (which is EXACTLY a multiple of the AES block size, i.e 16 bytes), you need to pad with a whole new block:
        
        00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0F 10 = 16 bytes
        -------------- original data ------------------

        becomes...

        00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0F 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10  = 32 bytes
        -------------- original data ------------------ ----------------- padding ---------------------

        
        The "length" parameter is the size in bytes of the data within "buffer" to be encrypted. 
        Of course, according to the buffer "parameter" constraints, it must be a multiple of the block size in AES (which means "length" % AES_BLOCK_SIZE == 0 ).

        returns 0 on success, or -1 if the buffer was NULL or if length % AES_BLOCK_SIZE != 0.

    */

    int Encrypt(uint8_t *plaintext, size_t length);

    /* 
        Decrypts a blob of data using AES.

        The "buffer" parameter is a pointer to the buffer which is to be decrypted. 
        Its content will be overwritten with the resulting decrypted buffer (padding won't be stripped).

        The "length" parameter is the length of "buffer", in bytes. 
        It needs to be a multiple of the AES cipher block size (which means "length" % 16 == 0).

        returns 0 on success, or -1 if the buffer was NULL or if length % AES_BLOCK_SIZE != 0.
    */

    int Decrypt(uint8_t *ciphertext, size_t length);

    // Convenience methods for encrypting/decrypting a file.
    int EncryptFile(const string& inputPath, const string& outputPath);
    int DecryptFile(const string& inputPath, const string& outputPath);

    // Manually reset the IV when you want to use the same instance of AES for encrypting, then decrypting.
    void SetIv(uint8_t *iv);
    
    private:

    // The chosen key size/
    AESKeySize keySize;
    
    // The chosen block cipher mode of operation.
    AESMode mode;

    // The chosen IV for some encryption modes like CBC, otherwise NULL. 
    uint8_t iv[AES_BLOCK_SIZE] = { 0 };

    /* 
        Nk represents the number of words (4 bytes) in the input encryption key.

        Will take the following values when constructing the AES instance:

        4 in 128 bits key mode.
        6 in 192 bits key mode.
        8 in 256 bits key mode.

    */

    uint8_t Nk; 

    /* 
        Nr represents the numbers of rounds needed for each key size in the AES cipher.

        Will take the following values constructing the AES instance:

        10 in 128 bits key mode.
        12 in 192 bits key mode.
        14 in 256 bits key mode.

    */

    uint8_t Nr; 

    /* The buffer that holds the generated round keys from the key expansion step. Will be dynamically allocated according to the key size. */
    uint8_t *RoundKeys = NULL;

    // Main initializer for all constructors
    void Init(AESKeySize keySize, AESMode mode, uint8_t *key);

    // The main block encryption method.
    void Cipher(uint8_t state[Nb][Nl]);
    void InvCipher(uint8_t state[Nb][Nl]);

    // Key expansion step, in order to produces keys for each round from the main one.
    void ExpandKey (uint8_t *key);

    // These two methods are used within the key expansion step.
    void RotWord(uint8_t *word);
    void SubWord(uint8_t *word);
    
    // Apply S-box substitution to our state matrix.
    void SubBytes(uint8_t state[Nb][Nl]);
    void InvSubBytes(uint8_t state[Nb][Nl]);

    // Apply rows shifting to our state matrix.
    void ShiftRows(uint8_t state[Nb][Nl]);
    void InvShiftRows(uint8_t state[Nb][Nl]);

    // Apply columns mixing to our state matrix.
    void MixColumns(uint8_t state[Nb][Nl]);
    void InvMixColumns(uint8_t state[Nb][Nl]);

    // XOR the state with the round key
    void AddRoundKey(uint8_t state[Nb][Nl], uint8_t roundNumber);

    // This method is used to multiply a number by X in the galois field G(2^8) (so in this field, X value is 2)
    uint8_t XTime(uint8_t number);

    // This method allows us to multiply any byte by another number (up to 15) in the galois field G(2^8)
    uint8_t GMultiply (uint8_t number, uint8_t multiplier); 

    // XOR current IV to a block.
    void AddIv(uint8_t *block);

    // encryption/decryption for each mode of operation, internally called by AES::Encrypt/AES::Decrypt.
    void EncryptECB(uint8_t *plaintext, size_t length);
    void DecryptECB(uint8_t *ciphertext, size_t length);

    void EncryptCBC(uint8_t *plaintext, size_t length);
    void DecryptCBC(uint8_t *ciphertext, size_t length);
    
};
