# EECE-5550-LAB#1 RSA

### Title and Author

* **Title:** *EECE RSA LAB*
* **Author:** *Christopher Bradley*

### Purpose of RSA LAB #1

* The Purpose of this lab is to gain hands-on experiences on the RSA algorithm. From the theoretic part of the RSA algorithm, we mathematically know how to generate public/private keys and how to perform encryption/decryption and signature generation/verification. This lab enhances the understanding of RSA by going step by step through the RSA algorithm on actual numbers, to apply the theories. The RSA algorithm will be implemented using the C program language.

**File Overview:**
* RSA.c contains all the functions
* The Follwoing certificate information for task #6 was obtained from facebook.com
  * c0.pem contains the first certificate
  * c1.pem contains the second certificate which belongs to an intermediate
  CA.
  * signature contains the extracted signature from the c0.pem file
  * c0_body.bin contains the extracted body from the c0.pem file

**Code SnapShots and Explanation**
* Tasks #1
  * Below shows the function for calculating d. The function takes in the values of p, q, and e. The function returns the value of d. d is calculated by using the multiplicative inverse of e mod (p-1)(q-1). d is used for decryption and signature verification.
    * ![Calculating d](/Images/LAB1/calculate_d.png)
* Tasks #2
  * Below shows the function for encrypting a message. The function takes in the values of n and e along with the message. The function returns the value of c. c is calculated by using the modular exponentiation of m^e mod n. c is used for encryption and signature generation.
    * ![Thread initialization](/Images/LAB1/encrypt_message.png)
* Tasks #3
  * Below shows the function for decrypting a message. The function takes in c (ciphertext) along with n and d. The function decrypts the message and then returns the ASCII value of the message.
    * ![ProjectClient Sockets](/Images/LAB1/decrypt_message.png)
* Tasks #4
  * Below shows the function for signing a message. The message along with n and d are passed into the function. The function returns the value of s. s is calculated by using the modular exponentiation of m^d mod n. s is used for signature generation. We call this function twice for two different cases.
    * ![ProjectClient Loop](/Images/LAB1/sign_message.png)
* Tasks #5
  * Below is the function for verifying a signature in task 5. The function takes in the message, signature, n, and e. The function prints if the signature is valid or not. We determine if it is valid by comparing the message to the decrypted signature. In this function we compare the ASCII values of the message and the decrypted signature.
    * ![ProjectMain Queue](/Images/LAB1/verify_signmature_task_5.png)
* Tasks # 6
  * Below is the function for verifying a signature in task 6. The function takes in the message, signature, n, and e. The function prints if the signature is valid or not. We determine if it is valid by comparing the message to the decrypted signature. In this function we compare the Hex values of the message and the decrypted signature.
    * ![ProjectMain Queue](/Images/LAB1/verify_signmature_task_6.png)
* Main
  * Below is the main program that initializes all of our constants and variables. The main program calls all of the functions for each task and prints the results to the screen.
    * ![ProjectMain Queue](/Images/LAB1/main.png)

### Execution Example

* The below snapshot shows the output of the RSA.c program. The program is run from the command line using the command `gcc RSA.c -lcrypto -o RSA`.
  * ![ProjectMain execution](/Images/LAB1/execution.png)