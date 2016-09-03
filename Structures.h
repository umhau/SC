/*
File: Metadata.h
Project: One Time Pad
Description:
This contains the structures and functions associated with storing metadata in the encrypted file.
Note: This metadata will also be encrypted.
*/

#pragma once

#include <vector>
#include <fstream>
#include <iostream>

//The pre-allocated size in bytes for the meta-data. I chose this arbitrarily.
//Note that in this implementation, not all bytes are actually used. The rest is allocated for compatibility with future improvements.
#define METADATA_PLAIN_SIZE 128 //Number of bytes allocated to unencrypted metadata (including 32-byte file signature)
#define METADATA_ENCRYPTED_SIZE 128 //Number of bytes allocated to encrypted metadata

//A constant 32 bytes at the top of the file. Serves as file type signature and text-editor-friendly identifier to what the file is.
const char constant_file_signature[32] = "OTP v1.0 BINARY CIPHER\n\n\0\0\0\0\0\0\0";

class MetaData{
public:
	//Default constructor
	MetaData () {}

	//Data members used by the program but not part of the encrypted file
	size_t padSize, plainSize, cipherSize;

	//Data members actually part of the encrypted file - right after the 32 byte file signature
	_Uint32t reverse_index; //The 4-byte starting index of a pad - counted backward from the end (that's why it's called reverse).
	_Uint32t index_verifier[8]; //A 32-byte plain sampling of the pad - verification for indicating that starting index is correct
	char pad_id[10]; //A max 10-character pad id code. Null-terminated if < 10 characters.
	char file_name[45]; //Max 45-character original filename. Null-terminated if < 30 characters.

	//Decrypting related Functions - all these assume the files were successfully opened
	bool DECverifySpaceRemaining(std::ifstream& pad_file, std::ifstream& cipher_file);
	bool DECdecryptFile(std::ifstream& pad_file, std::ifstream& cipher_file, std::ofstream& plain_file); //Returns whether successful.
	bool DECsearchStartIndex(std::ifstream& pad_file, std::ifstream& cipher_file); //Searches pad for proper starting index and returns whether successful.
	bool DECverifyFileSignature(std::ifstream& cipher_file); //Whether the cipher file has the proper 32-byte signature. Also sets reverse_index.
	bool DECpopulateMeta(std::ifstream& pad_file, std::ifstream& cipher_file); //Returns false if starting index fails verification.

	//Encrypting related Functions - all these assume the files were successfully opened
	bool ENCverifySpaceRemaining(std::ifstream& pad_file, std::ifstream& plain_file, _Uint32t reverse_i); //Also sets the reverse_index
	bool ENCencryptFile(std::ifstream& pad_file, std::ofstream& cipher_file, std::ifstream& plain_file, char* fn); //Returns whether successful. Assumes verifySpaceRemaining() has already returned true.
	

private:
	size_t getFileSize(std::ifstream& file); //Returns the size in bytes of an opened file

};

