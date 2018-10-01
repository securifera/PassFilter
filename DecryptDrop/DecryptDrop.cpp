/*	Author:  b0yd
	Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

#include <windows.h>
#include <stdio.h>

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



# pragma comment( lib, "cryptlib" )



int Decryptwithpriv(RSA::PrivateKey key, string in, string *out) {
	HexDecoder decoder;
	ByteQueue queue;

	AutoSeededRandomPool rng;

	try {
		decoder.Put((const byte *)in.data(), sizeof(in.data()), true);

		RSAES_OAEP_SHA_Decryptor d(key);

		StringSource(in, true,
			new HexDecoder(
				new PK_DecryptorFilter(rng, d,
					new StringSink(*out)
				) // PK_EncryptorFilter
			) // HexDecoder
		); // StringSource

	} catch (CryptoPP::Exception& e) {
		cerr << "Caught Exception..." << endl;
		cerr << e.what() << endl;
		return 1;
	}
	return 0;
}

int main(int argc, char* argv[])
{
	ByteQueue queue;
	RSA::PrivateKey privateKey;
	string privkeystring;

	if( argc < 5 ){
		cout << "\nUsage:\n\nDecryptDrop.exe -priv <Private Key Path> -enc <Encrypted File Path>" << std::endl;	
		return 1;
	}

	string key_str;
	char *enc_file= nullptr;

	//Parse inputs
	for( int i = 1; i < argc; i++ ){
		char *cur_str = argv[i];
		if( (strcmp(cur_str, "-priv") == 0) && (i+1 < argc) ){
			//Assign the path
			key_str.assign(argv[i+1]);	
			i++;

		} else if( (strcmp(cur_str, "-enc" ) == 0) && (i+1 < argc) ){
			enc_file = argv[i+1];
			i++;
		}
	}

	// Get the key into the useable format from file
	try {
		string sink;
		FileSource fsource(key_str.c_str(), true, new StringSink(privkeystring));
		StringSource(privkeystring, true, new HexDecoder(new StringSink(sink)));
		queue.Put((const byte*)sink.data(), sink.length(), true);
		queue.MessageEnd();
		privateKey.Load(queue);
		cout << "\n[+] Loaded private key successfully." << endl;
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << "\n[-] Error:\n" << endl;
		cerr << e.what() << endl;
		return false;
	}

	std::ifstream input(enc_file);
    std::string line;
	std::string decrypted;

    while( std::getline( input, line ) ) {
		//Decrypt the encrypted ke and iv using the private key retrieved from the file
		if (Decryptwithpriv(privateKey, line, &decrypted) == 1)
			return false;

		cout << decrypted << '\n';
		decrypted.clear();
    }


	return 0;
}

