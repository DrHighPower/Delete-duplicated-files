// C libraries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Windows libraries
#include <windows.h>
#include <direct.h>
#include <wincrypt.h>

// Linked list of all the files found
typedef struct FilesList{
    char* hash;
    struct FilesList *next;
} Files;

// Adds a node into de list
void addFile(Files** head, char* hash, int hashSize){
    Files* current = *head;

    // Save the new file info
    Files* new_file = (Files*)malloc(sizeof(Files));
    new_file->hash = (char*)malloc(hashSize + 1);
    strcpy(new_file->hash, hash);
    new_file->next = NULL;

    if(current == NULL){
        *head = new_file;
        current = *head;
    }else{
        current->next = new_file;
		current = current->next;
    }
}

// Checks if the hash is in the list
int inList(Files* head, char* hash){
    Files* current = head;

    while(current != NULL){
        if(strcmp(current->hash, hash) == 0) return 1;
        current = current->next;
    }

    return 0;
}

// Checks if a string is in the array
int inStringArray(char* string, char** stringArray){
    for(int i = 0; stringArray[i] != NULL; i++){
        if(strcmp(stringArray[i], string) == 0) return 1;
    }
    
    return 0;
}

// Function to calculate the SHA-256 hash of a file using Windows CryptoAPI
char* hashFile(const char* filename, int* sizeHash) {
    // Open the file for reading
    HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file: %s\n", filename);
        return NULL;
    }

    // Acquire a cryptographic context
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("CryptAcquireContext failed\n");
        CloseHandle(hFile);
        return NULL;
    }

    // Create a hash object
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("CryptCreateHash failed\n");
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return NULL;
    }

    BYTE buffer[BUFSIZ];
    DWORD bytesRead;

    // Read the file in chunks and update the hash with each chunk
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            printf("CryptHashData failed\n");
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return NULL;
        }
    }

    DWORD hashSize = 0;
    DWORD hashSizeSize = sizeof(DWORD);

    // Get the size of the hash
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeSize, 0)) {
        printf("CryptGetHashParam failed\n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return NULL;
    }

    BYTE *hash = (BYTE*)malloc(hashSize + 1);

    // Get the hash value
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
        printf("CryptGetHashParam failed\n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return NULL;
    }

    // Convert the hash bytes to a string representation
    char* hashString = (char*)malloc((hashSize * 2) + 1);
    for (DWORD i = 0; i < hashSize; i++) {
        sprintf(&hashString[i * 2], "%02x", hash[i]);
    }

    // Clean up resources
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    *sizeHash = (int)hashSize*2;
    return hashString;
}

int main() {

    // Stores the files that are gonna be ignored
    char *ignoredFiles[] = {
        "duplicateFileFinder.c",
        "duplicateFileFinder.exe",
        NULL
    };

    // Stores the found files hashs
	Files* foundFiles = NULL;

    // Stores the current directory that is going to be iterated through
    char* currentDirectory = strcat(_getcwd(NULL, 1024), "\\*");
    char* currentDirectoryName = _getcwd(NULL, 1024);
    
    WIN32_FIND_DATA findData; // Structure that holds information about a file found during the search
    HANDLE hFind;             // Represents the handle to an object

    // Find the first file in the directory
    hFind = FindFirstFile(currentDirectory, &findData);

    // Check if it openned the directory
    if(hFind == INVALID_HANDLE_VALUE){
        printf("Failed to open directory: %s\n", currentDirectory);
        return 1;
    }

    // Go through all the files
    do{
        // Exclude directories
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

        // Exclude the ignored files
        if(inStringArray(findData.cFileName, ignoredFiles)) continue;

        // Generate the file path
        char *filePath = (char*)malloc(strlen(currentDirectoryName) + strlen(findData.cFileName) + 3);
        sprintf(filePath, "%s\\%s", currentDirectoryName, findData.cFileName);

        // Get the file hash
        int hashSize;
        char* hash = hashFile(filePath, &hashSize);

        // Check if its in the list
        if(inList(foundFiles, hash)){

            // Remove the file
            printf("Deleted file: %s\n", findData.cFileName);
            remove(findData.cFileName);
        }else addFile(&foundFiles, hash, hashSize); // Add to the list

        // Free the allocated memory
        free(filePath);
        free(hash);
    }while(FindNextFile(hFind, &findData));

    // Close the handle
    FindClose(hFind);

    // Free the allocated memory
    free(currentDirectory);
    free(currentDirectoryName);
    free(foundFiles);

    return 0;
}
