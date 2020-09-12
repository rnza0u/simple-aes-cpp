#include <gtest/gtest.h>
#include <cstring>

#include "../src/Pkcs7Padding.h"
#include "../src/AES.h"
#include "../src/debug.h"

TEST(PKCS7PaddingTest, PadIncompleteBlock){

    uint8_t block [] = {
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x00, 0x00, 0x00
    };

    size_t dataLength = 12;

    uint8_t expectedPadding [] = {
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x01, 0x02, 0x04,
        0x04, 0x04, 0x04, 0x04
    };

    PKCS7Padding::AddBlockPadding(block, dataLength, AES_BLOCK_SIZE);

    ASSERT_EQ(0, memcmp(block, expectedPadding, AES_BLOCK_SIZE));

}

TEST(PKCS7PaddingTest, PadCompleteBlock){

    uint8_t block [] = {
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x00, 0x00, 0x00
    };

    size_t dataLength = 0;

    uint8_t expectedPadding [] = {
        0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10
    };

    PKCS7Padding::AddBlockPadding(block, dataLength, AES_BLOCK_SIZE);

    ASSERT_EQ(0, memcmp(block, expectedPadding, AES_BLOCK_SIZE));
}

TEST(PKCS7PaddingTest, RemovePaddingIncompleteBlock){
    
    uint8_t paddedBlock [] = {
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x01, 0x02, 0x04,
        0x00, 0x01, 0x02, 0x04,
        0x04, 0x04, 0x04, 0x04
    };

    size_t blockLength = AES_BLOCK_SIZE;

    PKCS7Padding::RemoveBlockPadding(paddedBlock, &blockLength);

    ASSERT_EQ(12, blockLength);
}

TEST(PKCS7PaddingTest, RemovePaddingCompleteBlock){
    
    uint8_t paddedBlock [] = {
        0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10
    };

    size_t blockLength = AES_BLOCK_SIZE;

    PKCS7Padding::RemoveBlockPadding(paddedBlock, &blockLength);

    ASSERT_EQ(0, blockLength);
}