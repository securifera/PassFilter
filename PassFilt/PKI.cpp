/*	Author:  b0yd
    Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

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

#include "hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "asn.h"
using CryptoPP::ByteQueue;

#include "PKI.h"

int Encryptwithpub(SecByteBlock *in, string *out) {
	try {
		AutoSeededRandomPool rng;
        //PASTE HEX STRING OF PUBLIC KEY GENERATED WITH PUBPRIVKEYGEN BELOW
		byte pubkeyarray[] = "PASTE HEX PUB KEY HERE";
		RSA::PublicKey publicKey;
		HexDecoder decoder;
		ByteQueue queue;

		decoder.Put(pubkeyarray, sizeof(pubkeyarray), true);
		decoder.MessageEnd();
		decoder.CopyTo(queue);
		queue.MessageEnd();
		publicKey.Load(queue);

		////////////////////////////////////////////////
		// Encryption
		RSAES_OAEP_SHA_Encryptor e(publicKey);

		StringSource(in->data(), in->size(), true,
			new PK_EncryptorFilter(rng, e,
				new HexEncoder(new StringSink(*out)
				) // HexEncdoer
			) // PK_EncryptorFilter
		); // StringSource


	}
	catch (CryptoPP::Exception& e) {
		cerr << "Caught Exception..." << endl;
		cerr << e.what() << endl;
		return 1;
	}
	return 0;
}
