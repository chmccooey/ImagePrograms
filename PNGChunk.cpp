#include "PNGChunk.h"
#include <utility>
#include <vector>
#include <cmath> //for standard floor function
#include <ctime> //for writing the timestamp when creating PNG files
#include <zlib.h> //for Huffman decompression of the IDAT chunk data

unsigned int fromBigEndian(const unsigned int input)
{
	unsigned int value = 0u;
	unsigned char data[4];
	memcpy(data, &input, 4);
	std::swap(data[0], data[3]);
	std::swap(data[1], data[2]);
	memcpy(&value, data, 4);
	return value;
}
void fromBigEndianV(unsigned int *input)
{
	unsigned int v = fromBigEndian(*input);
	*input = v;
}
bool colorTypeSupported(ColorType type, unsigned char bit_depth)
{
	bool supported = (
		type == CT_Gray ||
		type == CT_RGB ||
		type == CT_Indexed ||
		type == CT_Gray_A ||
		type == CT_RGBA
		);
	if (supported)
	{
		if (type == CT_Gray)
			supported = (bit_depth == 1 || bit_depth == 2 || bit_depth == 4 || bit_depth == 8);
		else if (type == CT_Indexed)
			supported = (bit_depth == 1 || bit_depth == 2 || bit_depth == 4 || bit_depth == 8);
		else if (type == CT_RGB || type == CT_RGBA || type == CT_Gray_A)
			supported = (bit_depth == 8);
	}
	return supported;
}
PLTE::PLTE():table(nullptr), count(0){}
PLTE::~PLTE(){delete[] table;}

PNGChunk::PNGChunk() //this function is called whenever we create an instance of this object
{
	length = 0;
	for (int i = 0; i < 5; i++)
		type[i] = 0;
	data = nullptr;
	crc = 0;
}
PNGChunk::PNGChunk(const char* type_string, unsigned int data_length, const unsigned char* c_data, unsigned int crc_value)
{
	type[0] = type_string[0]; type[1] = type_string[1]; type[2] = type_string[2]; type[3] = type_string[3]; type[4] = 0;
	if (data_length > 0u && c_data != nullptr) //copy data if provided
	{		
		length = data_length;
		data = new unsigned char[length];
		memcpy(data, c_data, sizeof(unsigned char) * length);
	}
	else //no data chunk if not provided
	{
		length = 0;
		data = nullptr;
	}
	crc = crc_value;
}
PNGChunk::~PNGChunk() //this function is called whenever we delete an instance of this object
{
	if (data != nullptr)
		delete[] data;
}

int PNGChunk::readChunk(FILE* fp)
{
	int rc = 0;
	length = crc = 0u;
	type[0] = type[4] = 0;
	fread(&length, 4, 1, fp); fromBigEndianV(&length);
	fread(type, 4, 1, fp);
	data = new unsigned char[length];
	fread(data, length, 1, fp);
	fread(&crc, 4, 1, fp); fromBigEndianV(&crc);
	
	if (data == nullptr)
		rc = -1;
	
	return rc;
}
int PNGChunk::writeChunk(FILE* fp) const
{
	unsigned int tmp;
	tmp = fromBigEndian(length);
	fwrite(&tmp, 4, 1, fp);
	fwrite(type, 4, 1, fp);
	if (length > 0)
		fwrite(data, length, 1, fp);
	tmp = fromBigEndian(crc);
	fwrite(&tmp, 4, 1, fp);
}
void PNGChunk::printChunk()
{
	printf("DEBUG: Chunk read: length=%u type=%s crc=%u\n", length, type, crc);
}
std::string PNGChunk::toString()
{
	std::string text;
	text = "Length: ";
	text += std::to_string(length);
	text += " Type: ";
	text += type;
	text += " crc: ";
	text += std::to_string(crc);
	return text;
}
std::string PNGChunk::typeString()
{
	return std::string(type);
}
bool PNGChunk::isType(const char* str) const
{
	return (memcmp(str, type, sizeof(char) * 4) == 0);
}
unsigned int PNGChunk::getLength() const
{
	return length;
}
const unsigned char* PNGChunk::getData() const
{
	return data;
}
unsigned int PNGChunk::getCRC() const
{
	return crc;
}

//decoding functions
int PNGChunk::decodeIHDR(IHDR* ptr) const
{
	int rc = -1;
	memset(ptr, 0, sizeof(IHDR));
	if (isType("IHDR") && length == 13)
	{
		unsigned char color_type = 255;
		memcpy(&ptr->width, data + 0, 4); fromBigEndianV(&ptr->width);
		memcpy(&ptr->height, data + 4, 4); fromBigEndianV(&ptr->height);
		memcpy(&ptr->bit_depth, data + 8, 1);
		memcpy(&color_type, data + 9, 1);
		memcpy(&ptr->compression_method, data + 10, 1);
		memcpy(&ptr->filter_method, data + 11, 1);
		memcpy(&ptr->interlace_method, data + 12, 1);
		ptr->color_type = static_cast<ColorType>(color_type);
		rc = 0;
	}
	return rc;
}
int PNGChunk::decodePLTE(PLTE* ptr) const
{
	int rc = -1;
	memset(ptr, 0, sizeof(PLTE));
	if (isType("PLTE") && length >= 3 && length % 3 == 0)
	{
		ptr->count = static_cast<unsigned int>(length / 3);
		ptr->table = new Color[ptr->count];
		if (ptr->table != nullptr)
		{
			unsigned int iter = 0;
			for (unsigned int i = 0; i < ptr->count; i++)
			{
				ptr->table[i].r = data[iter + 0];
				ptr->table[i].g = data[iter + 1];
				ptr->table[i].b = data[iter + 2];
				iter += 3;
			}
			rc = 0;
		}
		else
			ptr->count = 0;
	}
	
	return rc;
}

//other structs
void IHDR::print() const
{
	printf("width=%d height=%d bit_depth=%u color_type=%u compression_method=%u filter_method=%u",
		width, height, bit_depth, color_type, compression_method, filter_method);
	printf(" interlace_method=\"");
	if (interlace_method == 1)
		printf("Adam7");
	else if (interlace_method == 0)
		printf("no interlace");
	else
		printf("Unknown %u", interlace_method);
	printf("\"\n");
}
unsigned char PNGChunk::getAverageValue(unsigned char left, unsigned char above)
{
	//floor((Raw(x-bpp)+Prior(x))/2)
	//float value = floor(((float)left + (float)above) / 2.0f);
	const int i_left = (int)left, i_above = (int)above;
	int value = (i_left + i_above) / 2;
	if (value < 0)
		printf("CRITICAL ERROR: Average filter value calculated was less than 0 (%d)\n", value);
	return static_cast<unsigned char>(value);
}
unsigned char PNGChunk::getPaethValue(unsigned char left, unsigned char above, unsigned char upper_left)
{
	int rc = -1;
	int p, pa, pb, pc;
	const int a = (int)left, b = (int)above, c = (int)upper_left;
	p = a + b - c; //initial estimate
	pa = abs(p - a); // distances to a, b, c
	pb = abs(p - b);
	pc = abs(p - c);
	// return nearest of a,b,c,
	if (pa < pb && pa < pc)
		rc = a;
	else if (pb < pa && pb < pc)
		rc = b;
	else if (pc < pa && pc < pb)
		rc = c;
	else
	{
		// breaking ties in order a, b, c.
		if (pa <= pb && pa <= pc)
			rc = a;
		else if (pb <= pc)
			rc = b;
		else
			rc = c;
	}
	if (rc < 0)
		printf("CRITICAL ERROR: Paeth filter value calculated was less than 0 (%d)\n", rc);
	return static_cast<unsigned char>(rc);
}

//decompress IDAT for decoding
int PNGChunk::decompressIDAT(const unsigned char* input_data, unsigned int input_len, unsigned char** output_data, unsigned int* output_len)
{
	int error_code = 0;
	z_stream d_stream; /* decompression stream */
	std::vector<uint8_t> uncompr;

    d_stream.zalloc = Z_NULL;
    d_stream.zfree = Z_NULL;
    d_stream.opaque = Z_NULL;
    d_stream.avail_in = 0;
    d_stream.next_in = Z_NULL;
    error_code = inflateInit(&d_stream);
	if (error_code != Z_OK)
		printf("ERROR: ZLIB Received error code %d from inflateInit\n", error_code);

    d_stream.avail_in = input_len; //compr.size();
    d_stream.next_in = (uint8_t*)input_data; //&compr[0];

    while (true)
	{
        uint8_t d_buffer[10] = {};
        d_stream.next_out = &d_buffer[0];
        d_stream.avail_out = 10;

        error_code = inflate(&d_stream, Z_NO_FLUSH);

        if (error_code == Z_STREAM_END)
		{
            for (int i = 0; i < (10 - d_stream.avail_out); i++)
                uncompr.push_back(d_buffer[i]);
            if (d_stream.avail_in == 0)
                break;
        }
		else if (error_code != Z_OK)
		{
			printf("ERROR: ZLIB Received error code %d from inflate\n", error_code);
			break;
		}

        for (int i = 0; i < (10 - d_stream.avail_out); i++)
            uncompr.push_back(d_buffer[i]);
    }
    error_code = inflateEnd(&d_stream);
	if (error_code != Z_OK)
		printf("ERROR: ZLIB Received error code %d from inflateEnd\n", error_code);

    //printf("Uncompressed data (size = %lu)\n", uncompr.size());
    //for (int i = 0; i < uncompr.size(); i++)
         //printf("unc at %d=%d\n", i, uncompr[i]);
	//for (int i = 0; i < uncompr.size(); i += 3)
         //printf("unc at %d=(%d %d %d)\n", i, uncompr[i], uncompr[i+1], uncompr[i+2]);
	 
	//allocate the buffer
	*output_len = uncompr.size();
	if (*output_len > 0)
	{
		 unsigned char* b = (unsigned char*)malloc(sizeof(unsigned char) * *output_len);
		 for (int i = 0; i < uncompr.size(); i++)
			 b[i] = uncompr[i];
		 *output_data = b;
	}
	else
		*output_data = NULL;
	 
	return error_code;
}

//compress IDAT for encoding
int PNGChunk::compressIDAT(const unsigned char* input_data, unsigned int input_len, unsigned char** output_data, unsigned int* output_len)
{
	int error_code = 0, rc = 0;
	z_stream d_stream; /* decompression stream */
	std::vector<uint8_t> compr;

    d_stream.zalloc = Z_NULL;
    d_stream.zfree = Z_NULL;
    d_stream.opaque = Z_NULL;
    d_stream.avail_in = 0;
    d_stream.next_in = Z_NULL;
    error_code = deflateInit(&d_stream, Z_DEFAULT_STRATEGY);
	if (error_code != Z_OK)
	{
		printf("ERROR: ZLIB Received error code %d from deflateInit\n", error_code);
		rc = -1;
	}

    d_stream.avail_in = input_len;
    d_stream.next_in = (uint8_t*)input_data;

    while (true)
	{
        uint8_t d_buffer[10] = {};
        d_stream.next_out = &d_buffer[0];
        d_stream.avail_out = 10;

        error_code = deflate(&d_stream, Z_FINISH);
        if (error_code == Z_STREAM_END)
		{
            for (int i = 0; i < (10 - d_stream.avail_out); i++)
                compr.push_back(d_buffer[i]);
            if (d_stream.avail_in == 0)
                break;
        }
		else if (error_code != Z_OK)
		{
			printf("ERROR: ZLIB Received error code %d from deflate\n", error_code);
			rc = -1;
			break;
		}

        for (int i = 0; i < (10 - d_stream.avail_out); i++)
            compr.push_back(d_buffer[i]);
    }
    error_code = deflateEnd(&d_stream);
	if (error_code != Z_OK)
	{
		printf("ERROR: ZLIB Received error code %d from deflateEnd\n", error_code);
		rc = -1;
	}

    printf("DEBUG: Compressed data (size = %lu)\n", compr.size());
    //for (int i = 0; i < compr.size(); i++)
        //printf("comp at %d=%d\n", i, compr[i]);
	//for (int i = 0; i < compr.size(); i += 3)
        //printf("comp at %d=(%d %d %d)\n", i, compr[i], compr[i+1], compr[i+2]);
	 
	//allocate the buffer
	*output_len = compr.size();
	if (*output_len > 0)
	{
		 unsigned char* b = (unsigned char*)malloc(sizeof(unsigned char) * *output_len);
		 for (int i = 0; i < compr.size(); i++)
			 b[i] = compr[i];
		 *output_data = b;
	}
	else
		*output_data = NULL;
	 
	return rc;
}

int PNGChunk::removeFilters(unsigned char* data, unsigned int len, const IHDR* header_info)
{
	int rc = 0;
	int j;
	unsigned int bytes_per_pixel = 1, bytes_per_row;
	unsigned int filter_counts[5];
	unsigned char* const_data = (unsigned char*)malloc(sizeof(unsigned char) * len);
	memcpy(const_data, data, len);
	memset(filter_counts, 0, sizeof(unsigned int) * 5);
	switch(header_info->color_type)
	{
	case CT_Gray: bytes_per_pixel = 1; break;
	case CT_RGB: bytes_per_pixel = 3; break;
	case CT_Indexed: bytes_per_pixel = 1; break;
	case CT_Gray_A: bytes_per_pixel = 2; break;
	case CT_RGBA: bytes_per_pixel = 4; break;
	}
	if (header_info->bit_depth == 16)
		bytes_per_pixel *= 2;
	bytes_per_row = header_info->width * bytes_per_pixel;
	printf("DEBUG: bytes_per_pixel=%u bytes_per_row=%u\n", bytes_per_pixel, bytes_per_row);
	
	unsigned int iter = 0;						
	for (unsigned int i = 0; i < header_info->height; i++)
	{
		const unsigned char filter_type = data[iter]; //modify the bytes depending on the data
		iter++;
		
		//do based on filter
		switch(filter_type)
		{
		case 0: //None
			//printf("Working on Scanline %u with None filter\n", i);
			iter += bytes_per_row;
			filter_counts[0]++;
			break;
		case 1: //Sub
		{
			//printf("Working on Scanline %u with Sub filter\n", i);
			for (j =0; j < bytes_per_row; j++)
			{
				if (j - bytes_per_pixel < bytes_per_row)
					data[iter] += data[iter - bytes_per_pixel];
				iter++;
			}
			filter_counts[1]++;
			break;
		}
		case 2: //Up
		{
			//printf("Working on Scanline %u with Up filter\n", i);
			for (j = 0; j < bytes_per_row; j++)
			{
				if (i > 0)
					data[iter] += data[iter - bytes_per_row - 1];
				iter++;
			}
			filter_counts[2]++;
			break;
		}
		case 3: //Average
		{
			//printf("Working on Scanline %u with Average filter\n", i);
			unsigned char left, prior;
			for (j = 0; j < bytes_per_row; j++)
			{
				left = prior = 0; //pixels out of range default to 0
				if (j - bytes_per_pixel < bytes_per_row)
					left = data[iter - bytes_per_pixel];
				if (i > 0)
					prior = data[iter - bytes_per_row - 1];
				data[iter] += getAverageValue(left, prior);
				iter++;
			}
			filter_counts[3]++;
			break;
		}
		case 4: //Paeth
		{
			//printf("Working on Scanline %u with Paeth filter\n", i);
			unsigned char left, prior, upper_left, paeth_prediction;
			for (j = 0; j < bytes_per_row; j++)
			{
				left = prior = upper_left = 0; //pixels out of range default to 0
				if (j - bytes_per_pixel < bytes_per_row)
				{
					left = data[iter - bytes_per_pixel];
					if (i > 0)
					{
						prior = data[iter - bytes_per_row - 1];
						upper_left = data[iter - bytes_per_pixel - bytes_per_row - 1];
					}
				}
				else if (i > 0)
					prior = data[iter - bytes_per_row - 1];
				
				//paeth order is left, above, upper left
				paeth_prediction = getPaethValue(left, prior, upper_left);
				data[iter] += paeth_prediction;
				
				iter++;
			}
			filter_counts[4]++;
			break;
		}
		default: //Bad filter
			printf("ERROR: Got a bad filter of %u for scanline %u\n", (unsigned int)filter_type, i);
			rc = -1;
			break;
		}
	}
	printf("\n");
	printf("Filter statistics:\n");
	printf("\tNone: %u\n", filter_counts[0]);
	printf("\tSub: %u\n", filter_counts[1]);
	printf("\tUp: %u\n", filter_counts[2]);
	printf("\tAverage: %u\n", filter_counts[3]);
	printf("\tPaeth: %u\n", filter_counts[4]);
	free(const_data);
	
	return rc;
}

int readPNG(const std::string &filepath, IMGData* img_data, std::string* error_string)
{
	int rc = -1;
	
	img_data->width = img_data->height = 0;
	img_data->rgba_raster = NULL;
	
	FILE* fp = fopen(filepath.c_str(), "rb");
	if (fp == nullptr)
	{
		if (error_string != nullptr)
			*error_string = std::string("Failed to open PNG file ") + filepath + std::string(" for reading");
	}
	else
	{
		unsigned char header_bytes[8];
		
		//read the header information
		memset(header_bytes, 0, sizeof(unsigned char) * 8);
		fread(header_bytes, 1, 8, fp);
		
		//print bytes
		//DEBUG
		printf("DEBUG: Bytes are: ");
		for (int i = 0; i < 8; i++)
			printf("%#04x ", header_bytes[i]);
		printf("\n");
		//DEBUG
		
		//verify its a PNG file
		if (header_bytes[0] == 0x89u && header_bytes[1] == 0x50 &&
			header_bytes[2] == 0x4e && header_bytes[3] == 0x47)
		{
			std::vector<PNGChunk*> chunk_vector;
			
			//read the chunks
			while (!feof(fp))
			{
				PNGChunk* chunk = new PNGChunk();
				chunk->readChunk(fp);
				chunk_vector.push_back(chunk);
			}
			
			//print all the chunks
			const unsigned int chunk_count = chunk_vector.size();
			for (unsigned int i = 0; i < chunk_count; i++)
				chunk_vector[i]->printChunk();
			
			if (chunk_count >= 1 && chunk_vector[0]->isType("IHDR"))
			{
				IHDR info;
				int error_code = chunk_vector[0]->decodeIHDR(&info);
				info.print(); //DEBUG
				if (error_code == 0 && colorTypeSupported(info.color_type, info.bit_depth) && info.interlace_method == 0)
				{
					unsigned char* rgba_raster = new unsigned char[info.width * info.height * 4];
					if (rgba_raster != nullptr)
					{
						unsigned char* idat_data;
						unsigned int idat_total_bytes = 0u, iter;
						std::vector<PNGChunk*> idats;
						PNGChunk* pallete_chunk = nullptr; //only for indexed images
						
						//update the data based on the chunks
						for (unsigned int i = 1; i < chunk_vector.size(); i++)
						{
							if (chunk_vector[i]->isType("IDAT"))
							{
								idats.push_back(chunk_vector[i]);
								idat_total_bytes += chunk_vector[i]->getLength();
							}
							else if (chunk_vector[i]->isType("PLTE"))
							{
								if (pallete_chunk == nullptr)
									pallete_chunk = chunk_vector[i];
							}
						}
						printf("DEBUG: idat total=%u total_size=%u\n", (unsigned int)idats.size(), idat_total_bytes);
						
						//combine the IDAT data
						idat_data = (unsigned char*)calloc(idat_total_bytes, sizeof(unsigned char));
						iter = 0u;
						for (unsigned int i = 0; i < idats.size(); i++)
						{
							memcpy(idat_data + iter, idats[i]->getData(), idats[i]->getLength() * sizeof(unsigned char));
							iter += idats[i]->getLength();
						}
						
						//decompress IDAT data with zlib
						unsigned char* output_data = NULL;
						unsigned int output_len = 0;
						error_code = PNGChunk::decompressIDAT(idat_data, idat_total_bytes, &output_data, &output_len);
						
						//copy the data into the RGBA raster
						if (output_data != NULL && output_len > 0u)
						{
							const unsigned int total_len = info.width * info.height;
							const bool have_color = (info.color_type == CT_RGB || info.color_type == CT_RGBA);
							const bool indexed = (info.color_type == CT_Indexed);
							PLTE* pallete_data = nullptr;
							bool pallete_ok = false, reading_ok = false;
							int iter = 0;
							
							error_code = PNGChunk::removeFilters(output_data, output_len, &info);
							
							//read the color pallete if there is a color table
							if (info.color_type == CT_Indexed)
							{
								if (pallete_chunk != NULL)
								{
									pallete_data = new PLTE();
									error_code = pallete_chunk->decodePLTE(pallete_data);
									if (error_code == 0)
										pallete_ok = true;
									else
										*error_string = std::string("Failed to decode the PLTE chunk");
								}
								else
									*error_string = std::string("PNG file has indexed colors but not color table data was found");
							}
							else
								pallete_ok = true;
							
							//handle the data copy to RGBA dependent on the input format
							if (pallete_ok)
							{
								int k = 0;
								printf("DEBUG: Scanline filter=(");
								for (unsigned int i = 0; i < info.height; i++)
								{
									printf("%u ", (unsigned int)output_data[iter]); //DEBUG
									const unsigned char filter_type = output_data[iter]; //modify the bytes depending on the data
									
									iter++;//skip filter
									for (unsigned int j = 0; j < info.width; j++)
									{
										if (have_color) //RGB and RGBA
										{
											rgba_raster[k + 0] = output_data[iter]; iter++;
											rgba_raster[k + 1] = output_data[iter]; iter++;
											rgba_raster[k + 2] = output_data[iter]; iter++;
											if (info.color_type == CT_RGB)
												rgba_raster[k + 3] = 255; //alpha channel
											else if (info.color_type == CT_RGBA)
											{ rgba_raster[k + 3] = 255;output_data[iter]; iter++; } //alpha channel
										}
										else if (!indexed)//Grey and Grey with alpha
										{
											rgba_raster[k + 0] = rgba_raster[k + 1] = rgba_raster[k + 2] = output_data[iter];
											iter++;
											if (info.color_type == CT_Gray_A)
											{ rgba_raster[k + 3] = output_data[iter]; iter++; } //alpha channel
											else
												rgba_raster[k + 3] = 255;
										}
										else if (indexed) //Color from a table using indexing
										{
											const unsigned int index = output_data[iter]; iter++;
											if (index < pallete_data->count)
											{
												rgba_raster[k + 0] = pallete_data->table[index].r;
												rgba_raster[k + 1] = pallete_data->table[index].g;
												rgba_raster[k + 2] = pallete_data->table[index].b;
											}
											else
												rgba_raster[k + 0] = rgba_raster[k + 1] = rgba_raster[k + 2] = 255;
											rgba_raster[k + 3] = 255;
										}
										k += 4;
									}
								}
								printf(")\n");//DEBUG
								reading_ok = true;
							}
							
							//print RGBA
							//printf("DEBUG: RGBA:\n");
							//for (unsigned int i = 0; i < total_len*4; i += 4)
								//printf("     (%u %u %u %d)\n", rgba_raster[i + 0], rgba_raster[i + 1], rgba_raster[i + 2], rgba_raster[i + 3]);
							
							//finished
							free(output_data);
							free(idat_data);
							if (pallete_data != nullptr)
								delete pallete_data;
							
							//assign data variables if everything is successful
							if (reading_ok)
							{
								img_data->rgba_raster = rgba_raster;
								img_data->width = info.width;
								img_data->height = info.height;
								rc = 0;
							}
						}
						else
							*error_string = std::string("Failed to decompress IDAT chunks");
					}
					else
						*error_string = std::string("Failed to allocate ") + std::to_string(info.width * info.height) + std::string(" bytes for pixel buffer");
				}
				else
				{
					if (!colorTypeSupported(info.color_type, info.bit_depth))
					{
						*error_string = std::string("PNG file has a color type that is not supported");
					}
					else if (info.interlace_method != 0)
						*error_string = std::string("Interlacing is not supported");
					else if (error_code != 0)
						*error_string = std::string("Failed to decode IHDR chunk from PNG file");
				}
			}
			else
				*error_string = std::string("PNG has no IHDR chunk");
			
			//delete chunks
			for (unsigned int i = 0; i < chunk_vector.size(); i++)
				delete chunk_vector[i];
		}
		else
			*error_string = std::string("File is not a PNG file");
		
		//close file
		fclose(fp);
	}
	
	return rc;
}
int writePNG(const std::string &filepath, const IMGData* data, std::string* error_string)
{
	const int raster_row_size = sizeof(unsigned char) * data->width * 4;
	int rc = -1, i, iter_dest, iter_src, error_code;
	unsigned char* bytes, *inflated_data;
	PNGChunk* header_chunk, *ts_chunk, *iend_chunk;
	unsigned char header_bytes[8];
	unsigned short year;
	unsigned int tmp, inflated_size = 0;
	time_t     now = time(0);
    struct tm  tstruct;
	std::vector<PNGChunk*> idat_chunk_array;
	
	FILE* fp = fopen(filepath.c_str(), "wb");
	if (fp == nullptr)
	{
		*error_string = std::string("Failed to open file \"") + filepath + std::string("\" for writing");
		return rc;
	}
	header_chunk = ts_chunk = iend_chunk = nullptr;
	
	//create the header bytes
	header_bytes[0] = 0x89; header_bytes[1] = 0x50;
	header_bytes[2] = 0x4e; header_bytes[3] = 0x47;
	header_bytes[4] = 0x0d; header_bytes[5] = 0x0a;
	header_bytes[6] = 	0x1a; header_bytes[7] = 0x0a;
	
	//create the header chunk
	bytes = new unsigned char[100];
	tmp = fromBigEndian((unsigned int)data->width);
	memcpy(bytes + 0, &tmp, 4);
	tmp = fromBigEndian((unsigned int)data->height);
	memcpy(bytes + 4, &tmp, 4);
	bytes[8] = 8; //bit depth
	bytes[9] = static_cast<unsigned char>(CT_RGBA); //color type (RGBA = 6)
	bytes[10] = 0; //compression_method
	bytes[11] = 0; //filter method
	bytes[12] = 0; //interlace_method 0=none
	header_chunk = new PNGChunk("IHDR", 13, bytes, 0);
	
	//create the timestamp chunk
    tstruct = *localtime(&now);
	year = (unsigned short)tstruct.tm_year + 1900u;
	bytes[0] = (unsigned char)(year >> 8);
	bytes[1] = (unsigned char)(year);
	bytes[2] = (unsigned char)tstruct.tm_mon;
	bytes[3] = (unsigned char)tstruct.tm_mday;
	bytes[4] = (unsigned char)tstruct.tm_hour;
	bytes[5] = (unsigned char)tstruct.tm_min;
	bytes[6] = (unsigned char)tstruct.tm_sec;
	ts_chunk = new PNGChunk("tIME", 7, bytes, 0);
	
	//delete bytes since we are done with it
	delete[] bytes; bytes = nullptr;
	
	//create IDAT (4 for RGBA and height for filter byte 0 at the beginning of each scanline
	inflated_size = (raster_row_size * data->height) + data->height;
	inflated_data = new unsigned char[inflated_size];
	if (inflated_data != nullptr)
	{
		unsigned char *compressed_data = nullptr;
		unsigned int compressed_size = 0;
		
		//create data with filter bytes all being zero. Not very effiencient and would be better if filters were selected and applied
		iter_dest = iter_src = 0;
		for (i = 0; i < data->height; i++)
		{
			inflated_data[iter_dest] = 0; iter_dest++;//filter type is always 0 for this encoder
			memcpy(inflated_data + iter_dest, data->rgba_raster + iter_src, raster_row_size);
			iter_src += raster_row_size;
			iter_dest += raster_row_size;
		}
		
		//compress the data buffer using ZLIB Huffman compression
		error_code = PNGChunk::compressIDAT(inflated_data, inflated_size, &compressed_data, &compressed_size);
		if (error_code == 0)
		{
			const unsigned int ideal_chunk_size = 32768;
			PNGChunk *idat_chunk;
			if (compressed_size <= ideal_chunk_size) //make one IDAT chunk
			{
				idat_chunk = new PNGChunk("IDAT", compressed_size, compressed_data, 0); //create IDAT
				idat_chunk_array.push_back(idat_chunk);
			}
			else //make many IDAT chunks
			{
				unsigned int num_chunks = compressed_size / ideal_chunk_size;
				unsigned int remaining_data = compressed_size, iter = 0;
				if (compressed_size % ideal_chunk_size != 0)
					num_chunks++;
				printf("DEBUG: Writing a total of %u IDAT chunks\n", num_chunks);
				for (unsigned int i = 0; i < num_chunks; i++)
				{
					if (remaining_data >= ideal_chunk_size)
					{
						idat_chunk = new PNGChunk("IDAT", ideal_chunk_size, compressed_data + iter, 0); //create IDAT
						remaining_data -= ideal_chunk_size;
					}
					else
					{
						idat_chunk = new PNGChunk("IDAT", remaining_data, compressed_data + iter, 0);
						remaining_data = 0;
					}
					idat_chunk_array.push_back(idat_chunk);
					iter += ideal_chunk_size;
				}
			}
			iend_chunk = new PNGChunk("IEND", 0, nullptr, 0); //create IEND
			rc = 0;
		}
		else
			*error_string = std::string("Failed to compress PNG data");
		free(compressed_data);
		delete[] inflated_data;
	}
	else
		*error_string = std::string("Failed to allocate memory for image. The image is too large.");
	
	//write to the file and close
	if (rc == 0)
	{
		//write the header
		fwrite(header_bytes, 8, 1, fp);
		
		//write the chunks
		header_chunk->writeChunk(fp);
		ts_chunk->writeChunk(fp);
		for (i = 0; i < idat_chunk_array.size(); i++)
			idat_chunk_array[i]->writeChunk(fp);
		iend_chunk->writeChunk(fp);
	}
	fclose(fp);
	
	//free memory and return
	delete header_chunk;
	delete ts_chunk;
	for (i = 0; i < idat_chunk_array.size(); i++)
		delete idat_chunk_array[i];
	delete iend_chunk;
	
	return rc;
}
