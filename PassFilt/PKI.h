/*	Author:  b0yd
	Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

#ifndef _PKI_INC
#define _PKI_INC

#include "secblock.h"
#include <string>

using CryptoPP::SecByteBlock;

int Encryptwithpub(SecByteBlock *in, std::string *out);


#endif _PKI_INC