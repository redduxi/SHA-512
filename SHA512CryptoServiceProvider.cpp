#include "SHA512CryptoServiceProvider.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>
#pragma warning( push )
#pragma warning( disable : 4101)
// Your function
#pragma warning( pop )
#define BYTE8 (int64)0xFF
#define COUNT_WORDS 80
#define BLOCK_SIZE 1024
#define MESSAGE_LENGTH 128
#define ONE_BYTE 0x80

SHA512CryptoServiceProvider::SHA512CryptoServiceProvider()
{
    InitialState(_H);
}

void SHA512CryptoServiceProvider::InitialState(int64 H[])
{
    H[0] = 0x6a09e667f3bcc908;
    H[1] = 0xbb67ae8584caa73b;
    H[2] = 0x3c6ef372fe94f82b;
    H[3] = 0xa54ff53a5f1d36f1,
    H[4] = 0x510e527fade682d1;
    H[5] = 0x9b05688c2b3e6c1f;
    H[6] = 0x1f83d9abfb41bd6b;
    H[7] = 0x5be0cd19137e2179;
}
/*
 * CH, MAJ, SSIG0, SSIG1, BSIG0, BSIG1 - logical functions, each function
 * operates on 64-bit words, which are represented as x, y, and z.
 * The result of each function is a new 64-bit word.
*/
SHA512CryptoServiceProvider::int64 SHA512CryptoServiceProvider::CH(int64 x, int64 y, int64 z)
{
    return (x & y) ^ (~x & z);
}

SHA512CryptoServiceProvider::int64 SHA512CryptoServiceProvider::MAJ(int64 x, int64 y, int64 z)
{
    return (x & (y | z)) | (y & z);
}

SHA512CryptoServiceProvider::int64 SHA512CryptoServiceProvider::BSIG1(int64 x)
{
    return CircularRightRotate(x, 14) ^ CircularRightRotate(x, 18) ^ CircularRightRotate(x, 41);
}

SHA512CryptoServiceProvider::int64 SHA512CryptoServiceProvider::BSIG0(int64 x)
{
    return CircularRightRotate(x, 28) ^ CircularRightRotate(x, 34) ^ CircularRightRotate(x, 39);
}

SHA512CryptoServiceProvider::int64 SHA512CryptoServiceProvider::SSIG0(int64 x)
{
    return CircularRightRotate(x, 1) ^ CircularRightRotate(x, 8) ^ (x >> 7);
}

SHA512CryptoServiceProvider::int64 SHA512CryptoServiceProvider::SSIG1(int64 x)
{
    return CircularRightRotate(x, 19) ^ CircularRightRotate(x, 61) ^ (x >> 6);
}

void SHA512CryptoServiceProvider::AppendByte(unsigned char byte)
{
    message[_word] &= ~(BYTE8 << ((8 - 1 - _byte) * 8) );
    message[_word] |= ((int64)byte << ((8 - 1 - _byte) * 8) );
    _byte = _byte + 1;
    _word += _byte / 8;
    _byte = _byte % 8;
}

void SHA512CryptoServiceProvider::AppendWord(int64 word)
{
    message[_word++] = word;
}

SHA512CryptoServiceProvider::int64 SHA512CryptoServiceProvider::CircularRightRotate(int64 x, int n)
{
    return (x >> n) | (x << (64 - n));
}

void SHA512CryptoServiceProvider::ProcessBlock(const int64 *Message, int64 *H)
{
    int64 words[COUNT_WORDS];
    int64 state[8];

    for (int64 i = 0; i < 16; i++)
    {
        words[i] = Message[i];
    }

    for (int64 i = 16; i < COUNT_WORDS; i++)
    {
        words[i] = SSIG1(words[i - 2]) + words[i - 7] + SSIG0(words[i - 15]) + words[i - 16];
    }

    for(int64 i = 0 ; i < 8 ; i++)
    {
        state[i] = H[i];
    }

    for (int64 i = 0; i < COUNT_WORDS; i++)
    {
        int64 majRes   = MAJ(state[0], state[1], state[2]);
        int64 resFunc  = words[i] + _K[i] + state[7] + CH(state[4], state[5], state[6]) + BSIG1(state[4]);

        state[7] = state[6];
        state[6] = state[5];
        state[5] = state[4];
        state[4] = state[3] + resFunc;
        state[3] = state[2];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = BSIG0(state[0]) + majRes + resFunc;
    }

    for(uint8_t i = 0 ; i < 8 ; i++)
    {
        H[i] += state[i];
    }
}
/*
 * Increases the total length of the padded message multiple of 1024.
 * Append one byte to message (0x80).
 * Add message length at the end of the block (128 bits).
 * Process each blocks and output final hash.
*/
std::string SHA512CryptoServiceProvider::Hashing(std::string inputMessage)
{
    const char* mess;
    int inputMessageLength = inputMessage.length();
    for (int i = 0; i < inputMessageLength; i++)
    {
        mess += inputMessage[i];
    }

    int64 intermediateLength, K, messageLength;

    intermediateLength = (int64)inputMessageLength * 8;
    messageLength = intermediateLength + 1 + MESSAGE_LENGTH;
    K = ((~messageLength + 1) % BLOCK_SIZE + BLOCK_SIZE) % BLOCK_SIZE;
    messageLength += K;

    message = (int64 *)malloc(messageLength / 8);
    _word = _byte = 0;

    for (int i = 0; i < inputMessageLength; i++)
        AppendByte(inputMessage[i]);
    AppendByte(ONE_BYTE);                                                                             //Append one byte
    for (int i = 0; i < K / 8; i++)
        AppendByte(0);
    AppendWord(0);
    AppendWord(intermediateLength);

    for (int i = 0; i < (int)(messageLength / 64); i += 16)
    {
        ProcessBlock(message + i, _H);
    }

    std::stringstream is;
    is << std::setfill('0') << std::hex;

    for (int64 x : _H) {
        for (uint8_t i = 0; i < 64; i += 8)
        {
            is << std::setw(2) << (unsigned int) (((*(((int64 *) & x))) >> (64 - 8 - i)) & BYTE8);
        }
    }

    return is.str();                                                                                 //Return final hash
}

