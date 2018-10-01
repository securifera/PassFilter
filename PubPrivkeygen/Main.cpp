/*	Author:  b0yd
    Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

# pragma comment( lib, "cryptlib" )




#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "sha.h"
using CryptoPP::SHA1;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "SecBlock.h"
using CryptoPP::SecByteBlock;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

#include "asn.h"
using CryptoPP::ByteQueue;

#include "base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;


int main(int argc, char* argv[])
{
	try {
		////////////////////////////////////////////////
		// Generate keys
		AutoSeededRandomPool rng;

		InvertibleRSAFunction parameters;
		parameters.GenerateRandomWithKeySize(rng, 4096);

		RSA::PrivateKey privateKey(parameters);
		RSA::PublicKey publicKey(parameters);

		ByteQueue queue, queue2;
		//Base64Encoder encoder, encoder2;
		HexEncoder encoder, encoder2;
		FileSink file1 ("privatekey.txt"), file2 ("publickey.txt");
		string keystring ="0x";
		privateKey.Save(queue);
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		encoder.CopyTo(file1);
		encoder.CopyTo(StringSink(keystring));
		file1.MessageEnd();

		publicKey.Save(queue2);
		queue2.CopyTo(encoder2);
		encoder2.MessageEnd();
		encoder2.CopyTo(file2);
		file2.MessageEnd();

		
	} catch (CryptoPP::Exception& e) {
		cerr << "Caught Exception..." << endl;
		cerr << e.what() << endl;
	}

	return 0;
}

