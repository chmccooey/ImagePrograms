#ifndef _PNG_CHUNK_H
#define _PNG_CHUNK_H

/* //C way of doing this

#include <stdio.h>
#include <string.h>

typedef struct PNGChunk
{
	
	
} PNGChunk;
*/

#include <cstdio>
#include <cstring>
#include <string>
#include "Color.h"

enum ColorType
{
	CT_Gray = 0,
	CT_RGB = 2,
	CT_Indexed = 3,
	CT_Gray_A = 4,
	CT_RGBA = 6,
};

struct IHDR
{
	unsigned int width, height;
	unsigned char bit_depth, compression_method;
	unsigned char filter_method, interlace_method;
	ColorType color_type;
	
	void print() const;
};
struct PLTE
{
	Color* table;
	unsigned int count;
	
	PLTE();
	~PLTE();
};

struct IMGData
{
	int width;
	int height;
	unsigned char* rgba_raster;
};

int readPNG(const std::string &filepath, IMGData* data, std::string* error_string);
int writePNG(const std::string &filepath, const IMGData* data, std::string* error_string);

//C++ way of doing this
class PNGChunk
{
public:
	PNGChunk(); //this function is called whenever we create an instance of this object
	PNGChunk(const char* type_string, unsigned int data_length, const unsigned char* data, unsigned int crc_value);
	~PNGChunk(); //this function is called whenever we delete an instance of this object
	
	int readChunk(FILE* fp);
	int writeChunk(FILE* fp) const;
	void printChunk();
	std::string toString();
	std::string typeString();
	bool isType(const char* str) const;
	unsigned int getLength() const;
	const unsigned char* getData() const;
	unsigned int getCRC() const;
	
	//decode
	int decodeIHDR(IHDR* ptr) const;
	int decodePLTE(PLTE* ptr) const;

	static int decompressIDAT(const unsigned char* input_data, unsigned int input_len, unsigned char** output_data, unsigned int* output_len);
	static int compressIDAT(const unsigned char* input_data, unsigned int input_len, unsigned char** output_data, unsigned int* output_len);
	static int removeFilters(unsigned char* data, unsigned int len, const IHDR* header_info);
	static unsigned char getAverageValue(unsigned char left, unsigned char above);
	static unsigned char getPaethValue(unsigned char left, unsigned char above, unsigned char upper_left);
	
private:
	//data here
	unsigned int length;
	char type[5];
	unsigned char* data;
	unsigned int crc;
};

#endif
