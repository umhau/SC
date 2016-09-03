#include "Structures.h"


bool MetaData::DECverifyFileSignature(std::ifstream& cipher_file){
	cipherSize = getFileSize(cipher_file);
	//Check that cipher file is big enough to contain header
	if(cipherSize <= METADATA_PLAIN_SIZE + METADATA_ENCRYPTED_SIZE){
		return false;
	}
	//Check signature
	for(size_t i = 0; i < 32; i++){
		char fileByte;
		cipher_file.get(fileByte);
		if(fileByte != constant_file_signature[i]){
			return false;
		}
	}

	return true;
}

bool MetaData::DECpopulateMeta(std::ifstream& pad_file, std::ifstream& cipher_file){
	//Clear the error states of the files
	pad_file.clear();
	cipher_file.clear();

	//Read unencrypted header part
	cipher_file.seekg(36,std::ios::beg);
	cipher_file.read((char*)(&index_verifier),sizeof(index_verifier));
	
	//Verify the starting index
	pad_file.seekg(padSize - reverse_index, std::ios::beg);
	_Uint32t padDWord;
	for(size_t i = 0; i < 8; i++){
		pad_file.read((char *)(&padDWord),sizeof(padDWord));
		if(padDWord != index_verifier[i]){
			return false;
		}
	}

	//Read encrypted header part
	cipher_file.clear();
	pad_file.clear();
	cipher_file.seekg(128, std::ios::beg); //This is where the pad id begins
	pad_file.seekg(padSize - reverse_index + 32, std::ios::beg); //32 is right after the verifier
	char padByte, cipByte;
	for(size_t i = 0; i < 10; i++){ //pad id
		pad_file.get(padByte);
		cipher_file.get(cipByte);
		pad_id[i] = padByte ^ cipByte; //decrypt and store
	}
	pad_id[9] = '\0'; //just for safety
	for(size_t i = 0; i < 45; i++){ //filename
		pad_file.get(padByte);
		cipher_file.get(cipByte);
		file_name[i] = padByte ^ cipByte;
	}
	file_name[44] = '\0'; //just for safety
	
	return true;
}

bool MetaData::DECdecryptFile(std::ifstream& pad_file, std::ifstream& cipher_file, std::ofstream& plain_file){
	cipher_file.clear();
	pad_file.clear();
	plain_file.clear();

	try{
		pad_file.seekg(padSize - reverse_index + 87, std::ios::beg); //32 (verifier) + 10 (pad id) + 45 (filename) = 87
		cipher_file.seekg(256, std::ios::beg);

		//Decrypt and write the plain file
		char inputByte, padByte;
		int percentage = 0, perc_counter = 0;
		size_t byte_counter = 0;
		std::cout << "Processing..." << std::endl;
		std::cout << "0 %\r";
		while(byte_counter + 256 < cipherSize){
			byte_counter++;
			perc_counter++;
			cipher_file.get(inputByte);
			pad_file.get(padByte);
			plain_file.put(inputByte ^ padByte);
			//Update percent complete every 2048 bytes
			if(perc_counter == 2048){
				perc_counter = 0;
				std::cout << (100 * (byte_counter + 256) / cipherSize) << " %\r";
			}
		}
		//std::cout << "100 %" << std::endl << std::endl;
	}catch(...){
		return false;
	}
	return true;
}

bool MetaData::DECverifySpaceRemaining(std::ifstream& pad_file, std::ifstream& cipher_file){
	//Clear the error states of the files
	pad_file.clear();
	cipher_file.clear();

	//Get file sizes
	padSize = getFileSize(pad_file);
	cipherSize = getFileSize(cipher_file);

	//Read starting position from file
	cipher_file.clear();
	cipher_file.seekg(32, std::ios::beg);
	cipher_file.read((char *)(&reverse_index), sizeof(reverse_index));
	
	
	//Check bounds
	if(padSize <= reverse_index){ //Pad size smaller than specified index
		return false;
	}
	if(padSize + METADATA_PLAIN_SIZE <= cipherSize){ //Pad size smaller than encrypted part of cipher file
		return false;
	}

	return true;
}

bool MetaData::ENCverifySpaceRemaining(std::ifstream& pad_file, std::ifstream& plain_file, _Uint32t reverse_i){
	//Clear the error states of the files
	pad_file.clear();
	plain_file.clear();
	
	//Set the reverse index
	reverse_index = reverse_i;

	//Get file sizes
	padSize = getFileSize(pad_file);
	plainSize = getFileSize(plain_file);

	//Check bounds
	if(padSize <= reverse_i){
		return false;
	}
	if(reverse_i <= plainSize + METADATA_ENCRYPTED_SIZE){
		return false;
	}

	return true;
}

bool MetaData::ENCencryptFile(std::ifstream& pad_file, std::ofstream& cipher_file, std::ifstream& plain_file, char* fn){
	//Clear the error states of the files
	pad_file.clear();
	cipher_file.clear();
	plain_file.clear();
	
	//Variables
	char inputByte, padByte, outputByte;
	
	//Copy the fn to the file_name
	size_t i = 0;
	for(; i < 45; i++){
		if(fn[i] == '\0'){
			break;
		}
		file_name[i] = fn[i];
	}
	for(; i < 45; i++){
		file_name[i] = '\0';
	}
	
	try{
		//Write the unencrypted part of file header
		for(size_t i = 0; i < 32; i++){ // +32 bytes
			cipher_file.put(constant_file_signature[i]);
		}
		cipher_file.write((char *)(&reverse_index), sizeof(reverse_index)); // +4 bytes
		pad_file.seekg(padSize - reverse_index, std::ios::beg); //Seek to the proper location in the pad
		for(size_t i = 0; i < 32; i++){ // +32 bytes - this is the index verifier
			char temp;
			pad_file.get(temp);
			cipher_file.put(temp);
		}
		//Add padding for remainder of unencrypted header: 128 (total) - 68 (used)
		for(size_t i = 0; i + 68 < METADATA_PLAIN_SIZE; i++){
			cipher_file.put(i); //Just throw the index in - doesn't really matter what bytes are put in
		}

		//Encrypt and write the encrypted part of file header
		for(size_t i = 0; i < 10; i++){ // +10 bytes
			pad_file.get(padByte);
			cipher_file.put(pad_id[i] ^ padByte);
		}
		for(size_t i = 0; i < 45; i++){ // +45 bytes
			pad_file.get(padByte);
			cipher_file.put(file_name[i] ^ padByte);
		}
		//Add padding for remainder of header: 128 (total) - 55 bytes (used)
		for(size_t i = 0; i + 55 < METADATA_ENCRYPTED_SIZE; i++){
			cipher_file.put(i);
		}


		//Encrypt and write the plain file
		int percentage = 0, perc_counter = 0;
		size_t byte_counter = 0;
		std::cout << "Processing..." << std::endl;
		std::cout << "0 %\r";
		while(byte_counter < plainSize){
			byte_counter++;
			perc_counter++;
			plain_file.get(inputByte);
			pad_file.get(padByte);
			cipher_file.put(inputByte ^ padByte);
			//Update percent complete every 2048 bytes
			if(perc_counter == 2048){
				perc_counter = 0;
				std::cout << (100 * byte_counter / plainSize) << " %\r";
			}
		}
		std::cout << "100 %" << std::endl << std::endl;
	}catch(...){
		return false; //Some error occurred
	}
	return true;
}

size_t MetaData::getFileSize(std::ifstream& file){
	size_t sz;
	file.clear();
	file.seekg(0, std::ios::end);
	sz = file.tellg();
	file.seekg(0, std::ios::beg);
	return sz;
}