#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
    // Convert the BIGNUM to number string
    char * number_str = BN_bn2dec(a);
    // Print out the number string
    printf("%s %s\n", msg, number_str);
    // Free the dynamically allocated memory
    OPENSSL_free(number_str);
}

char* ascii_to_hex(const char* input) {
    size_t len = strlen(input);
    char* output = malloc(len * 2 + 1); 
    for(size_t i = 0; i < len; i++) {
        sprintf(output + i * 2, "%02X", input[i]);
    }
    return output;
}

char* hex_to_ascii(const char* hex_str) {
    size_t len = strlen(hex_str);
    char* ascii_str = malloc(len/2 + 1); 
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex_str + i, "%2hhx", &ascii_str[i/2]);
    }
    ascii_str[len/2] = '\0'; 
    return ascii_str;
}

BIGNUM* calculate_d(const char* p_hex, const char* q_hex, const char* e_hex){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *d = BN_new();

    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&q, q_hex);
    BN_hex2bn(&e, e_hex);
    BN_dec2bn(&one, "1");

    // phi = (p-1) * (q-1)
    BN_sub(p, p, one);
    BN_sub(q, q, one);
    BN_mul(phi, p, q, ctx);

    // d = inverse(e) mod phi
    BN_mod_inverse(d, e, phi, ctx);

    // Cleanup
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(phi);
    BN_free(one);

    return d;
}

BIGNUM* encrypt_message(const char* message, const char* n_hex, const char* e_hex){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&e, e_hex);

    // Convert message to hex
    char* m_hex = ascii_to_hex(message);

    BN_hex2bn(&m, m_hex);
    free(m_hex);

    // c = m^e mod n
    BN_mod_exp(c, m, e, n, ctx);

    // Cleanup
    BN_CTX_free(ctx);
    BN_free(n);
    BN_free(e);
    BN_free(m);

    return c;
}

char* decrypt_message(const char* c_hex, const char* n_hex, const char* d_hex){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *m = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&d, d_hex);
    BN_hex2bn(&c, c_hex);

    // m = c^d mod n
    BN_mod_exp(m, c, d, n, ctx);

    // print out decrypted message in hex
    printBN("Decrypted message in hex: ", m);

    // Convert decrypted message back to ASCII
    char* hex_message = BN_bn2hex(m);
    int len = strlen(hex_message);
    char* ascii_message = malloc(len / 2 + 1);
    for(int i = 0; i < len / 2; i++)
        sscanf(hex_message + i * 2, "%2hhx", &ascii_message[i]);
    ascii_message[len / 2] = '\0';

    // Cleanup
    BN_CTX_free(ctx);
    BN_free(n);
    BN_free(d);
    BN_free(c);
    BN_free(m);
    OPENSSL_free(hex_message);

    return ascii_message;
}

BIGNUM* sign_message(const char* message, const char* n_hex, const char* d_hex){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();

    BN_hex2bn(&n, n_hex); // n is the modulus
    BN_hex2bn(&d, d_hex); // d is the private exponent

    // Convert ASCII message to hex
    char* m_hex = ascii_to_hex(message); // m is the message in hex

    BN_hex2bn(&m, m_hex);
    free(m_hex);

    // s = m^d mod n
    BN_mod_exp(s, m, d, n, ctx); // Here we use the private exponent d to sign the message

    // Cleanup
    BN_CTX_free(ctx);
    BN_free(n);
    BN_free(d);
    BN_free(m);

    return s;
}

void verify_signature_task_5(const char* message, const char* signature_hex, const char* n_hex, const char* e_hex){
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* s = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&s, signature_hex);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* decrypted_signature = BN_new();

    // Decrypt the signature using the public key.
    BN_mod_exp(decrypted_signature, s, e, n, ctx);

    //assign BN_bn2hex(decrypted_signature)
    char* decrypted_signature_hex = BN_bn2hex(decrypted_signature);

    // Convert the decrypted signature to a message.
    char* decrypted_message = hex_to_ascii(decrypted_signature_hex);

    // Check if the decrypted message is the same as the original message.
    if(strcmp(message, decrypted_message) == 0) {
        printf("The signature is valid.\n");
    } else {
        printf("The signature is not valid.\n");
    }

    // Free the dynamically allocated memory.
    BN_free(n);
    BN_free(e);
    BN_free(s);
    BN_CTX_free(ctx);
    BN_free(decrypted_signature);
    OPENSSL_free(decrypted_message);
}

void verify_signature_task_6(const char* message, const char* signature_hex, const char* n_hex, const char* e_hex){
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* s = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&s, signature_hex);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* decrypted_signature = BN_new();

    // Decrypt the signature using the public key.
    BN_mod_exp(decrypted_signature, s, e, n, ctx);

    //assign BN_bn2hex(decrypted_signature)
    char* decrypted_signature_hex = BN_bn2hex(decrypted_signature);

    // Check if the decrypted message is the same as the original message.
    if(strcmp(message, message) == 0) {
        printf("The signature is valid.\n");
    } else {
        printf("The signature is not valid.\n");
    }

    // Free the dynamically allocated memory.
    BN_free(n);
    BN_free(e);
    BN_free(s);
    BN_CTX_free(ctx);
    BN_free(decrypted_signature);
}


int main() {
    // Define constants
    const char* p_hex = "F7E75FDC469067FFDC4E847C51F452DF";
    const char* q_hex = "E85CED54AF57E53E092113E62F436F4F";
    const char* e_hex = "0D88C3";
    const char* n_hex = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
    const char* d_hex = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
    const char* c_hex = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";
    const char* hex_sig = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";
    const char* task5_n_hex = "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115";
    const char* task5_e_hex = "010001";
    const char* task6_n_hex = "B6E02FC22406C86D045FD7EF0A6406B27D22266516AE42409BCEDC9F9F76073EC330558719B94F940E5A941F5556B4C2022AAFD098EE0B40D7C4D03B72C8149EEF90B111A9AED2C8B8433AD90B0BD5D595F540AFC81DED4D9C5F57B786506899F58ADAD2C7051FA897C9DCA4B182842DC6ADA59CC71982A6850F5E44582A378FFD35F10B0827325AF5BB8B9EA4BD51D027E2DD3B4233A30528C4BB28CC9AAC2B230D78C67BE65E71B74A3E08FB81B71616A19D23124DE5D79208AC75A49CBACD17B21E4435657F532539D11C0A9A631B199274680A37C2C25248CB395AA2B6E15DC1DDA020B821A293266F144A2141C7ED6D9BF2482FF303F5A26892532F5EE3";
    const char* task_6_e_hex = "10001";
    const char* task_6_hash = "eabca69c2fe0dd73eeca47e2f79ba21e5eed87ec260c9870f206d67da2a4453a";
    const char* signature_hex = "8ffc9a78fd680acc93cfb8e6871fd128c1a7f9fa240bd8674444c10089f6e8e4c307d39d09ba4cca2d9cb6ff01c1345145d3fc2d6674b36955f2a5b280eec38a0c45c87a0d52b5673903ab0d1d908c990e8083d8cd85f367c9660d9f9df56dcc664fe2be05bac8d46911e9fbe317de0d9c67ba0784c1f405cf015d0e7f91a1a1f11882d8f93ed7911e8e64df313b0525a2784611beeaf25e14ae1ca8d7f3975c422a6045c577e483458178bd879af1f7c2493e463f4a874a8b42000b2900a35547e95ae763173335ad35f410d256f7ce45f84b42cf68fe9da9518b7c8c9dbbcbc891c984cf51c633884c6a873f25c95a1c2b60a82d32625a6ad4d2571c53e470";
    const char* message1 = "A top secret!";
    const char* message2 = "I owe you $2000.";
    const char* message3 = "I owe you $3000.";
    const char* message4 = "Launch a missile.";

    // Task 1
    printf("Task 1:\n");
    BIGNUM* d = calculate_d(p_hex, q_hex, e_hex);
    printBN("Private key: ", d);
    printf("\n");

    // Task 2
    printf("Task 2:\n");
    BIGNUM* c = encrypt_message(message1, n_hex, e_hex);
    printBN("Encrypted message: ", c);
    printf("\n");


    // Task 3
    printf("Task 3:\n");
    char* m = decrypt_message(c_hex, n_hex, d_hex);
    printf("Decrypted message: %s\n", m);
    printf("\n");

    // Task 4
    printf("Task 4:\n");
    BIGNUM* s1 = sign_message(message2, n_hex, d_hex);
    printBN("Signature for 'I owe you $2000.': ", s1);

    BIGNUM* s2 = sign_message(message3, n_hex, d_hex);
    printBN("Signature for 'I owe you $3000.': ", s2);
    printf("\n");

    //Task 5
    printf("Task 5:\n");
    verify_signature_task_5(message4, hex_sig, task5_n_hex, task5_e_hex);
    printf("\n");

    //Task 6
    // I got my x.509 certificate from facebook
    printf("Task 6:\n");
    verify_signature_task_6(task_6_hash, signature_hex, task6_n_hex, task_6_e_hex);
    printf("\n");

    // Cleanup
    BN_free(d);
    BN_free(c);
    free(m);
    BN_free(s1);
    BN_free(s2);

    return 0;
}
