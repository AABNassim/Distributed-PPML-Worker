//
// Created by root on 30/06/19.
//

#include "MLSP.h"


MLSP::MLSP() {


    // Initiate connection with csp
    if ((csp_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(csp_port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, csp_ip, &serv_addr.sin_addr)<=0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return;
    }

    if (connect(csp_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return;
    }
}

void MLSP::send_message() {

    send(csp_sock , hello, strlen(hello) , 0 );

    printf("Hello message sent\n");
    valread = read(csp_sock , buffer, 1024);
    printf("%s\n", buffer);
}

bool send_data(int sock, void *buf, int buflen)
{
    unsigned char *pbuf = (unsigned char *) buf;

    while (buflen > 0)
    {
        int num = send(sock, pbuf, buflen, 0);

        pbuf += num;
        buflen -= num;
    }

    return true;
}


bool send_long(int sock, long value)
{
    value = htonl(value);
    return send_data(sock, &value, sizeof(value));
}

/*long min(long a, long b) {
    if (a < b) {
        return a;
    }
    return b;
}*/


bool MLSP::send_file(int sock, char* path)
{
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    rewind(f);
    if (filesize == EOF)
        return false;
    if (!send_long(sock, filesize))
        return false;
    if (filesize > 0)
    {
        char buffer[1024];
        do
        {
            size_t num = (filesize < sizeof(buffer)) ?  filesize : sizeof(buffer);
            num = fread(buffer, 1, num, f);
            if (num < 1)
                return false;
            if (!send_data(sock, buffer, num))
                return false;
            filesize -= num;
        }
        while (filesize > 0);
    }
    return true;
}


bool read_data(int sock, void *buf, int buflen)
{
    unsigned char *pbuf = (unsigned char *) buf;

    while (buflen > 0)
    {
        int num = recv(sock, pbuf, buflen, 0);
        if (num == 0)
            return false;

        pbuf += num;
        buflen -= num;
    }

    return true;
}

bool MLSP::read_long(int sock, long *value)
{
    if (!read_data(sock, value, sizeof(value)))
        return false;
    *value = ntohl(*value);
    return true;
}


bool MLSP::read_file(int sock, char* path)
{
    FILE *f = fopen(path, "wb");
    long filesize;
    if (!read_long(sock, &filesize))
        return false;
    if (filesize > 0)
    {
        char buffer[1024];
        do
        {
            int num = (filesize < sizeof(buffer)) ?  filesize : sizeof(buffer);
            if (!read_data(sock, buffer, num))
                return false;
            int offset = 0;
            do
            {
                size_t written = fwrite(&buffer[offset], 1, num-offset, f);
                if (written < 1)
                    return false;
                offset += written;
            }
            while (offset < num);
            filesize -= num;
        }
        while (filesize > 0);
    }
    return true;
}




void MLSP::test_send_file() {
    send_file(csp_sock, "./cipher.txt");
}

void MLSP::test_key_exchange() {
    long logp = 30; ///< Scaling Factor (larger logp will give you more accurate value)
    long logn = 10; ///< number of slot is 1024 (this value should be < logN in "src/Params.h")
    long logq = 300; ///< Ciphertext modulus (this value should be <= logQ in "scr/Params.h")
    long n = 1 << logn;
    long numThread = 2;

    // Send signal
    if (send_long(csp_sock, 42)) {
        // Need to receive the keys

        // Encryption key
        char* path = "serkey/ENCRYPTION_KEY.txt";
        read_file(csp_sock, path);

        cout << "Got the encryption key !" << endl;

        // Read the encryption key

        // Construct and Generate Public Keys //
        srand(42);
        SetNumThreads(numThread);
        Ring ring;
        SecretKey secretKey(ring);
        Scheme scheme(secretKey, ring);

        scheme.read_encryption_key();
        Ciphertext test_cipher;
        complex<double> *mvec1 = new complex<double>[n];

        for (int i = 0; i < n; ++i) {
            complex<double> c;
            c.real(i);
            c.imag(0);
            mvec1[i] = c;
        }
        scheme.encrypt(test_cipher, mvec1, n, logp, logq);

        Ciphertext test_cipher_read;
        SerializationUtils::readCiphertextModified(test_cipher_read, "cipher_test.txt");

        // Serialize cipher
        SerializationUtils::writeCiphertext(test_cipher, "test_ciphertext.txt");
        send_file(csp_sock, "test_ciphertext.txt");


        // Multiplication
        read_file(csp_sock, "serkey/MULTIPLICATION_KEY.txt");
        scheme.read_multiplication_key();

        Ciphertext cipher_a;
        Ciphertext cipher_b;
        Ciphertext cipher_mult;

        complex<double> *mvec_a = new complex<double>[n];
        complex<double> *mvec_b = new complex<double>[n];

        for (int i = 0; i < n; ++i) {
            complex<double> c;
            c.real(i);
            c.imag(0);
            mvec_a[i] = c;
            mvec_b[i] = c;
        }

        scheme.encrypt(cipher_a, mvec_a, n, logp, logq);
        scheme.encrypt(cipher_b, mvec_b, n, logp, logq);

        scheme.mult(cipher_mult, cipher_a, cipher_b);
        scheme.reScaleByAndEqual(cipher_mult, logp);

        SerializationUtils::writeCiphertext(cipher_mult, "cipher_mult.txt");

        if (send_file(csp_sock, "cipher_mult.txt")) {
            cout << "Sent the mult cipheer" << endl;
        }
        else {
            cout << "ERROR, could not send mult cipher" << endl;
        }

        // Get left rotation keys
        for (long i = 0; i < logN - 1; ++i) {
            cout << "Rot " << i << endl;
            long idx = 1 << i;
            string filename = "serkey/ROTATION_" + to_string(idx) + ".txt";
            char* path = (char*) filename.c_str();
            read_file(csp_sock, path);
        }
        cout << "Received the rotation keys" << endl;
        scheme.read_left_rotation_key();

        // Test the rotation
        Ciphertext cipher_left_rot;
        scheme.leftRotateFast(cipher_left_rot, cipher_a, 4);
        SerializationUtils::writeCiphertext(cipher_left_rot, "cipher_rot.txt");

        // send the cipher
        if (send_file(csp_sock, "cipher_rot.txt")) {
            cout << "Sent the rotation cipher" << endl;
        }


        // Get right rotation keys
        for (long i = 0; i < logN - 1; ++i) {
            cout << "Rot " << i << endl;
            long idx = Nh - (1 << i);
            string filename = "serkey/ROTATION_" + to_string(idx) + ".txt";
            char* path = (char*) filename.c_str();
            read_file(csp_sock, path);
        }
        cout << "Received the rotation keys" << endl;
        scheme.read_right_rotation_key();

        // Test right rotation
        Ciphertext cipher_right_rot;
        scheme.rightRotateFast(cipher_right_rot, cipher_a, 4);
        SerializationUtils::writeCiphertext(cipher_right_rot, "cipher_right_rot.txt");

        // send the cipher
        if (send_file(csp_sock, "cipher_right_rot.txt")) {
            cout << "Sent the right rotation cipher" << endl;
        }

    }

}