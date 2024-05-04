#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define PRIVATE_KEY_LENGTH 32
#define PUBLIC_KEY_LENGTH 65
#define HASH_LENGTH 32
#define ADDRESS_LENGTH 25

static const char    *ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static unsigned char INDEXES[128] = { -1 };

unsigned char * getIndexes(){
        int i;

        for (i = 0; i < 58; i++)

                INDEXES[(int)ALPHABET[i]] = i;

        return INDEXES;
}

unsigned char divmod58(unsigned char *in, int inLen, int i){

        int rem = 0;

        for (; i<inLen; i++){

                rem = rem * 256 + in[i];

                in[i] = rem / 58;

                rem = rem % 58;

        }

        return rem & 0xFF;
}



unsigned char divmod256(unsigned char *in, int inLen, int i){

        int rem = 0;

        for (; i<inLen; i++){

                rem = rem * 58 + in[i];

                in[i] = rem / 256;

                rem = rem % 256;

        }

        return rem & 0xFF;

}



unsigned char * base58_encode(unsigned char *in, int inLen, int *outLen){

        if (inLen == 0)

                return NULL;



        unsigned char *inCopy = malloc(inLen);

        memcpy(inCopy, in, inLen);



        //count leading zeros

        int z = -1;

        while (z < inLen && inCopy[++z] == 0x00)

                ;
        unsigned char *inCopy = malloc(inLen);

        memcpy(inCopy, in, inLen);



        //count leading zeros

        int z = -1;

        while (z < inLen && inCopy[++z] == 0x00)

                ;

        int j = inLen * 2;

        int inLen_x2 = j;

        unsigned char *temp = malloc(inLen_x2);

        //skip leading zeros and encode from startAt

        int startAt = z;

        while (startAt < inLen){

                unsigned char mod = divmod58(inCopy, inLen, startAt);

                if (inCopy[startAt] == 0)

                        ++startAt;

                temp[--j] = ALPHABET[mod];

        }

        free(inCopy);

        while (j<inLen_x2 && temp[j] == '1')            j++;

        while (--z >= 0)

                temp[--j] = '1';

        *outLen = inLen_x2 - j;
        int len = inLen_x2 - j;

        unsigned char *out = malloc(len + 1);

        out[len] = 0;

        memcpy(out, temp + j, len);

        free(temp);

        return out;
}



unsigned char * base58_decode(unsigned char *input, int inLen){

        if (inLen == 0)

                return NULL;

        unsigned char *input58 = malloc(inLen);

        unsigned char *indexes = getIndexes();

        int i = 0;

        for (; i<inLen; i++){

                input58[i] = indexes[input[i]];

        }

        //count leading zeros

        int z = -1;

        while (z<inLen && input58[++z] == 0x00)

                ;


        unsigned char *temp = malloc(inLen);

        int j = inLen;

        int startAt = z;

        while (startAt < inLen){
                char mod = divmod256(input58, inLen, startAt);

                if (input58[startAt] == 0)

                        ++startAt;

                temp[--j] = mod;
        }

        free(input58);

        while (j<inLen && temp[j] == 0)         j++;

        int len = inLen - j + z;

        unsigned char *out = malloc(len + 1);

        out[len] = 0;

        memcpy(out, temp + j - z, len);

        free(temp);

        return out;
}

// 计算比特币地址g
void generateBitcoinAddress(const unsigned char *publicKey) {

        // Step 2: 计算 SHA-256 哈希值g

        unsigned char hash1[SHA256_DIGEST_LENGTH];

        SHA256(publicKey, PUBLIC_KEY_LENGTH, hash1);

        printf("Step 2: SHA-256 哈希值：\n");

        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {

                printf("%02x", hash1[i]);

        }

        printf("\n");

        // Step 3: 计算 RIPEMD-160 哈希值g

        unsigned char hash2[RIPEMD160_DIGEST_LENGTH];

        RIPEMD160(hash1, SHA256_DIGEST_LENGTH, hash2);

        printf("Step 3: RIPEMD-160 哈希值：\n");

        for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; ++i) {

                printf("%02x", hash2[i]);

        }

        printf("\n");

        // Step 4: 添加地址版本号g

        unsigned char address[RIPEMD160_DIGEST_LENGTH + 1];

        address[0] = 0x00; // 主网标识符

        memcpy(address + 1, hash2, RIPEMD160_DIGEST_LENGTH);


        // Step 5: 计算两次 SHA-256 哈希值g

        unsigned char checksum1[SHA256_DIGEST_LENGTH];

        unsigned char checksum2[SHA256_DIGEST_LENGTH];

        SHA256(address, RIPEMD160_DIGEST_LENGTH + 1, checksum1);

        SHA256(checksum1, SHA256_DIGEST_LENGTH, checksum2);

        printf("Step 5: 两次 SHA-256 哈希值：\n");

        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {

                printf("%02x", checksum2[i]);

        }

        printf("\n");

        // Step 6: 取前四个字节作为校验位g

        unsigned char checksum[4];

        memcpy(checksum, checksum2, 4);

        // Step 7: 将校验位添加到地址中g

        memcpy(address + RIPEMD160_DIGEST_LENGTH + 1, checksum, 4);
        // Step 8: 使用 Base58 编码生成最终比特币地址g

        char *base58Address; // Base58 编码的地址可能比原始地址更大g

        int base58_Len;

        //base58_encode(address, RIPEMD160_DIGEST_LENGTH + 5, base58Address);

        base58Address = base58_encode(address, RIPEMD160_DIGEST_LENGTH + 5, &base58_Len);

        // 输出比特币地址

        printf("比特币地址: %s\n", base58Address);

        free(base58Address);
}

int decode_wif_private_key(const char *wifPrivateKey,int wifLen, unsigned char *privateKey) {

       unsigned char *decodedKey; // 解码后的数据最多为37字节

        int decodedLen = 37;
        // 解码 WIF 格式私钥
        decodedKey = base58_decode((unsigned char*)wifPrivateKey, wifLen);
        // 打印BASE58 解码 私钥

        printf("BTC WALLET BASE58_DECODE private key:\n");

        for (int i = 0; i < 37; ++i) {

                printf("%02x", decodedKey[i]);

        }
        printf("\n");
        unsigned char *WifAddress = base58_encode(decodedKey, decodedLen, &wifLen);

        // 打印 WIF 私钥

        printf("BTC WALLET WIF private key:\n");

        printf("%s", WifAddress);

        printf("\n");

        // 跳过版本字节（0x80），提取原始私钥

        memcpy(privateKey, decodedKey + 1, 32);

        // 去除校验位

        //memset(privateKey + 32, 0, 4);

        free(decodedKey);

        return 1;
}

int main() {
        // 示例的 WIF 格式私钥
        unsigned char  wifPrivateKey[] = "5JvwiHrRfNLJwhcJb1AALCwx2WaCxrPpCADRTkQPj46e72WQkEm";

        unsigned char privateKey[32];

        // 解码 WIF 格式私钥并提取原始私钥，并去除校验位

        if (!decode_wif_private_key(wifPrivateKey, strlen(wifPrivateKey), privateKey)) {

                return 1;

        }
        // 打印原始私钥
        printf("BTC WALLET private key:\n");
        for (int i = 0; i < 32; ++i) {

                printf("%02x", privateKey[i]);
        }
        printf("\n");
        generateBitcoinAddr(privateKey);
        return 0;
}
