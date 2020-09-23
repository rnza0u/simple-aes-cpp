#include <stdint.h>
#include <cstddef>
#include "Pkcs7Padding.h"

void PKCS7Padding::AddBlockPadding (uint8_t *buffer, size_t dataLength, size_t blockLength){
    
    uint8_t paddingValue = blockLength - dataLength;
    
    for (size_t i = 0; i < blockLength; i++)
        buffer[i] = i >= blockLength - paddingValue ? paddingValue : buffer[i];
};


void PKCS7Padding::RemoveBlockPadding (uint8_t *buffer, size_t *blockLength){
    
    size_t bl = (*blockLength);
    
    (*blockLength) = buffer[bl - 1] > bl ? bl : bl - buffer[bl - 1];
};