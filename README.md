# Simple Account Login and Password Cracker
Final Project for CMP SCI 3780 - Software Security  
**Authors: John I. and Joeseph B.**

## Requirements
```Python
# Library for csv file io
import csv
# Library for time
import time
# Library for hashBackend (openssl)
# https://cryptography.io/en/latest/hazmat/backends/
from cryptography.hazmat.backends import openssl
# Lirary for Hash functions like SHA-2 family, SHA-3 family, Blake2, and MD5
# https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
from cryptography.hazmat.primitives import hashes
```

## Description
The goal of this project was to simulate a login environment with plaintext, unsalted hash, and salted hash passwords and then attempt a brute force attack on the list of passwords.  

The project was seperated into the following tasks:  
## Task 1
**File: login_sim.py**  
**Author: Joseph B.**

#### Run the program
```
python login_sim.py
```
Simulate a login environment where the account database is simply a text file generated by Task 2. The program allows a person to login by selecting which accounts file they wish to "login" to. The program then simply reads the accounts file until the entered username is found.  
If the usernames don't match the program prints: `Login FAIL`.
### Plaintext Passwords
For the plaintext passwords the entered pasword is just compared with the password associated with the username in accounts0.txt.  
If the passwords match the program prints: `Login SUCCESS`.  
If the passwords don't match the program prints: `Login FAIL`.
### Unsalted Passwords
For the unsalted passwords the entered password is hashed using SHA-256 and then compared with the password associated with the username in accounts1.txt.  
If the passwords match the program prints: `Login SUCCESS`.  
If the passwords don't match the program prints: `Login FAIL`.
### Salted Passwords
For the salted passwords the salt associated with the entered username in accounts2.txt is appended to the entered password. The combination is then hashed using SHA-256 and then compared with the password associated with the username in accounts2.txt.  
If the passwords match the program prints: `Login SUCCESS`.  
If the passwords don't match the program prints: `Login FAIL`.

## Task 2
**File:   gen_acc.py**  
**Author: John I.**

#### Run the program
```
python gen_acc.py
```
Generate usernames and associated random passwords. The program promts the user to enter a minimum password length, a maximum password length, and the number of accounts to generate. The program then starts to generate each type of accounts file. Each username follows the pattern of user0, user1, user2, etc. The passwords are a random string generated using `os.urandom()`. Passwords are random lowercase letters and of a random length in the user designated range. 
### Plaintext Passwords
For the plaintext passwords the program simply writes the username and password in plaintext to the file as a comma seperated list where each account is on its own line in the file.

Example:  
```
user0,jpd
user1,ivx
user2,ani
```
### Unsalted Passwords
For the unsalted passwords the program hashes the random passwords and then writes the plaintext username and hashed password in hex to the file as a comma seperated list where each account is on its own line in the file.

Example:  
```
user0,ad6b01f526a0f05ce982d5a8666a3fc2d77eb0630e9b94b22d0fe0497ac3f7e8
user1,b764d3089b49ec21689006d88cbe21a10137174a25180866f9a45d3d40771c78
user2,33dcc1a09b951976fcb010636d531d9fc7689968321123729bde92d05548fb4d
```
### Salted Passwords
For the salted passwords the program generates a random one byte salt, appends it to the random password, hashes the salted password, and then writes the plaintext username, salted hashed password in hex, and the one byte salt to the file as a comma seperated list where each account is on its own line in the file.

Example:  
```
user0,6f37aa93e037d83474384811ea37eeda2fdb0a77689b87865507eeebf4f0360e,a
user1,28cee16b312c34aaf15ff02a514858bc1b0741185945fbbbcf5ad1a5fa4ac101,j
user2,dff875b42e2b07595a79c8e3860e227ab148e8f8db0bdb3dfd6c8d90766de739,q
```

**_All 3 accounts files use the same username and password combinations. The purpose of this is to be easily able to verify the actual password associated with the username in the hashed accounts by simply looking at the plaintext counterpart. Obviously this is not secure._**

## Task 3
**File:   password_cracker.py**  
**Author: John I.**

#### Run the program
```
python password_cracker.py
```
Crack all the passwords of the accounts generated by Task 2. THe program prompts the user to select which accounts to crack. The program then prompts the user to enter a minimum and maximum password length.
### Plaintext Passwords
The program doesn't crack plaintext passwords because you can simply look at the file to see the passwords.
### Unsalted Passwords
For the unsalted passwords the program reads accounts1.txt to an array of accounts and constructs a binary tree based on the password value. If more than one account share the same password then their usernames are stored in the same tree node. The program then generates a test password. For example, if the entered minimum is 3 and the entered maximum is 5 the first test password would be "aaa" and the last test password would be "zzzzz". Once a test password is generated it is then hashed using SHA-256. A search is then conducted on the binary tree looking for a matching hashed password. If a match is found, the username(s) and cracked password is written to an output file and the console as a comma seperated list where each account is on its own line in the file. The cracked node is then removed from the tree to improve future searches. The program then repeats for every possible test password.
### Salted Passwords
For the salted passwords the program reads accounts2.txt to an array of accounts. A binary tree is not constructed because it would not improve the search speed because of the nature of a salted password. Just like with the unsalted passwords a test password is generated. The program then iterates over the array. For each user the account's salt is appended to the plaintext password and then hashed using SHA-256 to produce an satled hash password. The salted hashed test password is compared to the users password. If it is match then the the username and cracked password is written to an output file and the console as a comma seperated list where each account is on its own line in the file. The cracked account is then removed from the array to improve futer searches. The program then repeats this for each account with each test password. 

**_The addition of the single character salt before hashing the password increases the time taken to crack the hash values significantly because each account had to be attacked seperately._**

