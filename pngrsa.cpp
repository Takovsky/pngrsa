#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <sstream>
#include <arpa/inet.h>
#include <vector>
#include <tuple>

const uint8_t chunkTypeOrLengthOrCrcSize = 4;
const uint8_t first8Bytes = 8;
const uint8_t chunkExludeDataSize = chunkTypeOrLengthOrCrcSize * 3; // type(4) +  lenght(4) + crc(4)
const uint8_t headerDataSize = 13;
const uint8_t headerSize = chunkTypeOrLengthOrCrcSize * 2 + headerDataSize;

struct RSAKeys
{
    std::pair<uint64_t, uint64_t> publicKey;
    std::pair<uint64_t, uint64_t> privateKey;
};

struct PngHeaderChunk
{
    uint32_t width;
    uint32_t height;
    uint8_t bitDepth;
    uint8_t colorType;
    uint8_t compressionMethod;
    uint8_t filterMethod;
    uint8_t interlaceMethod;
};

struct PngHeader
{
    uint32_t chunkLength;
    char chunkType[chunkTypeOrLengthOrCrcSize];
    PngHeaderChunk chunkData;
};

std::string toString(const char chunkType[chunkTypeOrLengthOrCrcSize])
{
    using namespace std;

    ostringstream output;
    for (int i = 0; i < chunkTypeOrLengthOrCrcSize; i++)
        output << chunkType[i];

    return output.str();
}

std::string toString(const PngHeaderChunk &pngHeaderChunk)
{
    using namespace std;

    ostringstream output;
    output << "\tData:" << endl;
    output << "\tWidth: " << pngHeaderChunk.width << endl;
    output << "\tHeight: " << pngHeaderChunk.height << endl;
    output << "\tBitDepth: " << (int)pngHeaderChunk.bitDepth << endl;
    output << "\tColorType: " << (int)pngHeaderChunk.colorType << endl;
    output << "\tCompressionMethod: " << (int)pngHeaderChunk.compressionMethod << endl;
    output << "\tFilterMethod: " << (int)pngHeaderChunk.filterMethod << endl;
    output << "\tInterlaceMethod: " << (int)pngHeaderChunk.interlaceMethod << endl;

    return output.str();
}

std::string toString(const PngHeader &pngHeader)
{
    using namespace std;

    ostringstream output;
    output << "Type: " << toString(pngHeader.chunkType) << endl;
    output << "Length: " << pngHeader.chunkLength << endl;

    return output.str() + toString(pngHeader.chunkData) + '\n';
}

void changeEndianess(PngHeader &header)
{
    header.chunkLength = ntohl(header.chunkLength);
    header.chunkData.width = ntohl(header.chunkData.width);
    header.chunkData.height = ntohl(header.chunkData.height);
}

uint64_t findGCD(uint64_t a, uint64_t b)
{
    while (a != b)
    {
        a > b ? a -= b : b -= a;
    }

    return a;
}

uint64_t reverseModulo(uint64_t e, uint64_t phi)
{
    uint64_t tmp = 0;

    for (uint64_t i = 1;; i++)
    {
        tmp = (i * e) % phi;
        if (tmp == 1)
            return i;
    }
}

RSAKeys generateRSAKeys()
{
    const uint64_t primeNumbers[20] = {
        17389,
        17387,
        17383,
        17377,
        17239,
        17257,
        17291,
        17293,
        17299,
        17317,
        17321,
        17327,
        17333,
        17341,
        17351,
        17359,
        17203,
        17207,
        17209,
        17231};

    uint64_t p = 0, q = 0;

    while (p == q)
    {
        p = primeNumbers[rand() % 20];
        q = primeNumbers[rand() % 20];
    }

    uint64_t phi = (p - 1) * (q - 1);
    uint64_t n = p * q;

    uint64_t e;
    for (e = 3; findGCD(e, phi) != 1; e += 2)
    {
    }

    uint64_t d = reverseModulo(e, phi);

    std::cout << "public key:\t(" << e << ", " << n << ")" << std::endl;
    std::cout << "private key:\t(" << d << ", " << n << ")" << std::endl;

    return RSAKeys{std::make_pair(e, n), std::make_pair(d, n)};
}

uint64_t encryptByte(uint64_t number, const std::pair<uint64_t, uint64_t> key)
{
    uint64_t result = 1;

    for (uint64_t helper = key.first; helper > 0; helper /= 2)
    {
        if (helper % 2)
            result = (number * result) % key.second;
        number = (number * number) % key.second;
    }

    return result;
}

void readFileHeader(std::fstream &file)
{
    PngHeader header;
    file.seekg(first8Bytes);
    file.read((char *)&header, headerSize);

    changeEndianess(header);
    std::cout << toString(header);
}

void printFileOfRange(std::fstream &file, const uint64_t begin, const uint32_t length)
{
    using namespace std;

    file.seekg(begin);

    for (int i = 0; i < length; i++)
    {
        char tmp;
        file.read((char *)&tmp, 1);
        cout << (int)tmp << " ";
    }
    cout << endl;
}

std::pair<uint64_t, uint32_t> findIDATStartingByteAndlength(std::fstream &file)
{
    char chunkName[4];
    uint64_t readBytes = first8Bytes + chunkExludeDataSize + headerDataSize;
    uint32_t IDATLength;
    while (strcmp(chunkName, "IDAT") != 0)
    {
        file.seekg(readBytes);
        file.read((char *)&IDATLength, 4);
        file.read((char *)&chunkName, 4);
        IDATLength = ntohl(IDATLength);
        readBytes += chunkExludeDataSize + IDATLength;
    }

    readBytes -= (chunkExludeDataSize + IDATLength);

    return std::make_pair(readBytes, IDATLength);
}

void rewriteFileExcludedIDATChunk(std::fstream &fileIn, std::fstream &fileOut, const uint64_t IDATBreakingByte, const uint32_t IDATLength)
{
    char beginning[IDATBreakingByte];
    fileIn.seekg(0);
    fileOut.seekg(0);
    fileIn.read((char *)&beginning, IDATBreakingByte);
    fileOut.write((char *)&beginning, IDATBreakingByte);

    fileIn.seekg(0, fileIn.end);
    uint64_t endingLength = fileIn.tellg();
    uint64_t afterIDATByte = IDATBreakingByte + chunkExludeDataSize + IDATLength;
    endingLength -= afterIDATByte;
    char ending[endingLength];

    fileIn.seekg(afterIDATByte);
    fileIn.read((char *)&ending, endingLength);
    fileOut.write((char *)&ending, endingLength);
}

void encryptFileIDATData(std::fstream &fileIn, std::fstream &fileOut, const uint64_t IDATStartingByte, const uint32_t IDATLength, const std::pair<uint64_t, uint64_t> key)
{
    uint32_t IDATLengthHtonlMultipliedToUint64 = htonl(IDATLength * 8);

    fileOut.seekg(IDATStartingByte);
    fileOut.write((char *)&IDATLengthHtonlMultipliedToUint64, 4);
    fileOut.write("IDAT", 4);
    fileIn.seekg(IDATStartingByte + chunkTypeOrLengthOrCrcSize * 2);

    for (int i = 0; i < IDATLength; i++)
    {
        uint8_t tmp;
        uint64_t encryptedByte;

        fileIn.read((char *)&tmp, 1);
        encryptedByte = encryptByte(tmp, key);
        fileOut.write((char *)&encryptedByte, 8);
    }

    uint32_t crc;
    fileIn.read((char *)&crc, chunkTypeOrLengthOrCrcSize);
    fileOut.write((char *)&crc, chunkTypeOrLengthOrCrcSize);
}

void decryptFileIDATData(std::fstream &fileIn, std::fstream &fileOut, const uint64_t IDATStartingByte, const uint32_t IDATLength, const std::pair<uint64_t, uint64_t> key)
{
    uint32_t IDATLengthHtonl = htonl(IDATLength);

    fileOut.seekg(IDATStartingByte);
    fileOut.write((char *)&IDATLengthHtonl, 4);
    fileOut.write("IDAT", 4);
    fileIn.seekg(IDATStartingByte + chunkTypeOrLengthOrCrcSize * 2);

    for (int i = 0; i < IDATLength; i++)
    {
        uint64_t tmp;
        uint8_t decryptedByte;

        fileIn.read((char *)&tmp, 8);
        decryptedByte = encryptByte(tmp, key);
        fileOut.write((char *)&decryptedByte, 1);
    }

    uint32_t crc;
    fileIn.read((char *)&crc, chunkTypeOrLengthOrCrcSize);
    fileOut.write((char *)&crc, chunkTypeOrLengthOrCrcSize);
}

int handleFile(const std::string &fileName)
{
    using namespace std;

    fstream fileIn;
    fileIn.open(fileName, fstream::in);

    if (not fileIn.is_open())
    {
        cerr << "Couldnt open file " << fileName << endl;
        fileIn.close();
        return -1;
    }

    readFileHeader(fileIn);

    uint64_t IDATStartingByte;
    uint32_t IDATLength;
    std::tie(IDATStartingByte, IDATLength) = findIDATStartingByteAndlength(fileIn);

    string encryptedFileName = fileName.substr(0, fileName.length() - 4) + "_e.png";
    fstream encryptedFile;
    encryptedFile.open(encryptedFileName, fstream::out | fstream::in);

    if (not encryptedFile.is_open())
    {
        cerr << "Couldnt open file " << encryptedFileName << endl;
        fileIn.close();
        return -1;
    }

    RSAKeys rsaKeys = generateRSAKeys();

    rewriteFileExcludedIDATChunk(fileIn, encryptedFile, IDATStartingByte, IDATLength);
    encryptFileIDATData(fileIn, encryptedFile, IDATStartingByte, IDATLength, rsaKeys.publicKey);

    string decryptedFileName = fileName.substr(0, fileName.length() - 4) + "_d.png";
    fstream decryptedFile;
    decryptedFile.open(decryptedFileName, fstream::out | fstream::in);

    if (not decryptedFile.is_open())
    {
        cerr << "Couldnt open file " << decryptedFileName << endl;
        fileIn.close();
        return -1;
    }

    rewriteFileExcludedIDATChunk(fileIn, decryptedFile, IDATStartingByte, IDATLength);
    decryptFileIDATData(encryptedFile, decryptedFile, IDATStartingByte, IDATLength, rsaKeys.privateKey);

    cout << endl
         << "encrypted file: " << encryptedFileName << endl;
    cout << "decrypted file: " << decryptedFileName << endl;

    fileIn.close();
    encryptedFile.close();
    decryptedFile.close();
}

int main(int argc, char *argv[])
{
    using namespace std;

    if (argc != 2)
    {
        cerr << "\tUsage:" << endl
             << "\t\tprog.out your_picture.png" << endl;

        return -1;
    }

    srand((unsigned)time(NULL));

    const string fileName = argv[1];

    return handleFile(fileName);
}