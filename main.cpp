/*
SIC Protocol Encryptor / Decryptor
Description:
A simple program for doing XOR file cryptography using a one-time pad.

Usage:
Encryption command format:
otp -enc [pad file] [index] [input file] [output file]
Sample:
otp.exe -enc pad.pad 5000 message.txt secure.cip

Decryption command format:
otp -dec [pad file] [input file]
Sample:
otp.exe -dec pad.pad secure.cip
*/

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include "Structures.h"

using namespace std;

const char usage_string[307] = "ERROR: Faulty hardware found between keyboard and chair.\nUsage:\nEncryption command format:\notp -enc [pad file] [index] [input file] [output file]\nSample:\notp.exe -enc pad.pad 5000 message.txt secure.cip\n\nDecryption command format:\notp -dec [pad file] [input file]\nSample:\notp.exe -dec pad.pad secure.cip";

void gracefulExit();

int main(int argc, char *argv[]){
	ifstream padFile, inputFile;
	ofstream outputFile;
	size_t startingPosition;
	
	//Verify command parameters
	if(((argc != 6) && (argc != 4)) ||
		(argc == 4 && strcmp(argv[1],"-dec")) ||
		(argc == 6 && strcmp(argv[1],"-enc"))){
			cerr << usage_string << endl;
			exit(1);
	}

	//See whether we're encrypting or decrypting
	if(strcmp(argv[1],"-enc") == 0){ //Encrypting
		//Set starting position
		startingPosition = atoi(argv[3]);
		
		//Open the pad, input, and output files
		padFile.open(argv[2], ios::in|ios::binary);
		inputFile.open(argv[4], ios::in|ios::binary);
		
		if(!padFile.is_open()){cerr << "ERROR: Could not open pad file!" << endl; exit(1);}
		if(!inputFile.is_open()){cerr << "ERROR: Could not open input file!" << endl; exit(1);}
		
		//Create a MetaData object
		MetaData meta;
		if(!meta.ENCverifySpaceRemaining(padFile,inputFile,startingPosition)){
			cerr << "ERROR: Reverse pad index " << startingPosition << " leaves insuffient pad space for encryption." << endl;
			exit(1);
		}
		//Encrypt
		outputFile.open(argv[5], ios::out|ios::binary);
		if(!outputFile.is_open()){cerr << "ERROR: Could not create output file!" << endl; exit(1);}
		if(!meta.ENCencryptFile(padFile,outputFile,inputFile,argv[4])){
			cerr << "ERROR: Something strange went wrong while encrypting and saving the output file. What did you DO!?" << endl;
		}else{
			cout << "Finished successfully! Next pad index: " << (meta.padSize - padFile.tellg()) << endl << endl;
		}

		//Close the files
		padFile.close();
		inputFile.close();
		outputFile.close();

	}else{ //Decrypting
		//Open the pad and input files
		padFile.open(argv[2], ios::in|ios::binary);
		inputFile.open(argv[3], ios::in|ios::binary);
		if(!padFile.is_open()){cerr << "ERROR: Could not open pad file!" << endl; exit(1);}
		if(!inputFile.is_open()){cerr << "ERROR: Could not open input file!" << endl; exit(1);}

		//Create a MetaData object
		MetaData meta;
		if(!meta.DECverifyFileSignature(inputFile)){
			cerr << "ERROR: Input file does not contain a valid encyrpted file signature!" << endl;
			exit(1);
		}
		if(!meta.DECverifySpaceRemaining(padFile, inputFile)){
			cerr << "ERROR: Pad space is insufficient for specified starting position " << meta.reverse_index << "." << endl;
			exit(1);
		}

		//Populate the MetaData object from the file
		if(!meta.DECpopulateMeta(padFile,inputFile)){
			cerr << "ERROR: Starting index " << meta.reverse_index << " is not valid for the specified pad and cipher." << endl;
			exit(1);
		}

		//Decrypt the file with permission
		char response;
		do{
			cout << "Found encrypted file: " << meta.file_name << endl << "OK to decrypt? (Y/N)" << endl;
			cin.get(response);
		}while(tolower(response) != 'y' && tolower(response) != 'n');

		if(response == 'y'){
			outputFile.open(meta.file_name, ios::out|ios::binary);
			if(!outputFile.is_open()){cerr << "ERROR: Unable to create/write output file: " << meta.file_name << endl; exit(1);}
			if(!meta.DECdecryptFile(padFile, inputFile, outputFile)){
				cerr << "ERROR: Something strange went wrong while decrypting and saving the output file. What did you DO!?" << endl;
				exit(1);
			}else{
				cout << "Finished successfully!" << endl << endl;
			}
		}else{
			cout << "Aborted by user. File not decrypted." << endl << endl;
		}

		//Close the files
		padFile.close();
		inputFile.close();
		outputFile.close();

	}

	return 0;
}
