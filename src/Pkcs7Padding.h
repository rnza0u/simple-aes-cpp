#pragma once

#include <stdint.h>

class PKCS7Padding {

    public:
    
    /* 
        Add PKCS#7 padding to a block.
    */
    static void AddBlockPadding (uint8_t *buffer, size_t dataLength, size_t blockLength);


    /* 
        Remove PKCS#7 padding from a block.
    */
    static void RemoveBlockPadding (uint8_t *buffer, size_t *blockLength);
};
