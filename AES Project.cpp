#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include <opencv2/core.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui.hpp>
#include <vector>
#include <cmath>
#include "filters.h"
#include "aes.h"
#include<chrono>
#include <iostream>
#include <string>

using namespace cv;
using namespace std;
using namespace CryptoPP;
using namespace chrono;

int j = 0;
int i = 0;
int t = 0;
float Total = 0;


struct color {
    uchar r;
    uchar g;
    uchar b;
};

color getColor(Mat mat, int x, int y) {
    color c;
    Vec3f intensity = mat.at<Vec3b>(x, y);
    c.b = intensity.val[0];
    c.g = intensity.val[1];
    c.r = intensity.val[2];
    return c;
}

//-------------------------------------------------
// Function for show image 

void showImage(Mat mat) {


    String windowName = "window"; //Name of the window

    namedWindow(windowName); // Create a window

    imshow(windowName, mat); // Show our image inside the created window.
    waitKey(0); // Wait for any keystroke in the window
    destroyWindow(windowName);
}

//-----------------------------------------------
// Function for convert image to string 

string img2Plain(Mat mat) {
    string plain = "";
    int rows = mat.rows, cols = mat.cols;

    for (int row = 0; row < rows; row++)
    {
        for (int col = 0; col < cols; col++)
        {
            for (int channel = 0; channel < 3; channel++) {
                plain += saturate_cast<char>(mat.at<Vec3b>(row, col)[channel]);

            }
        }
    }
    return plain;
}

//------------------------------------------------------
// Function to recover image from string 

Mat rec2Img(string recovered, Mat& matrix, int rows, int cols) {
    int length = recovered.length();
    int count = 0;

    for (int row = 0; row < rows; row++)
        for (int col = 0; col < cols; col++)
            for (int channel = 0; channel < 3; channel++) {
                matrix.at<Vec3b>(row, col)[channel] = (uchar)recovered[count];
                count++;
            }

    return matrix;
}

//-----------------------------------------------------------------------------------------------

vector<byte> S(128);
vector<byte> T(128);

// Initializing RC4 (IV)
int itRC4 = 0;
void RC4_Init(byte key[])
{
    for (i; i < 128; i++)
    {
        S[i] = i;
        T[i] = key[i % AES::DEFAULT_KEYLENGTH];
    }

    int temp = 0;
    for (i; i < 128; i++)
    {
        temp = (temp + S[i] + T[i]) % 128;
        swap(S[i], S[temp]);
    }
}

// RC4 code
vector<byte> RC4_keyGen(int num) {
    int t;
    vector<byte> val;
    for (int k = itRC4; k < itRC4 + num; k++)
    {
        i = (i + 1) % 128;
        j = (j + S[i]) % 128;
        swap(S[i], S[j]);
        t = (S[i] + S[j]) % 128;
        val.push_back(S[t]);
    }
    itRC4 = num;
    return val;
}
//--------------------------------------------------------------------------------
//Function of Encription 

string enc(byte key[AES::DEFAULT_KEYLENGTH], byte iv[AES::BLOCKSIZE], string plain) { // if not working replace AES::DEFAULT_KEYLENGTH with 16 and AES::BLOCKSIZE with 16 

    string cipher;
    try
    {
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
        StringSource s(plain, true, new StreamTransformationFilter(enc, new StringSink(cipher)));    // Make padding

#if 0
        StreamTransformationFilter filter(e);
        filter.Put((const byte*)plain.data(), plain.size());
        filter.MessageEnd();
        const size_t ret = filter.MaxRetrievable();
        cipher.resize(ret);
        filter.Get((byte*)cipher.data(), cipher.size());
#endif

    }
    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        cout << "error here" << endl;
        exit(1);
    }

    return cipher;
}

//------------------------------------------------------------------------------------------------
// Function of Decription

string dec(byte key[AES::DEFAULT_KEYLENGTH], byte iv[AES::BLOCKSIZE], string cipher) {
    string recover;
    try
    {
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
        StringSource s(cipher, true, new StreamTransformationFilter(dec, new StringSink(recover)));
#if 0
        StreamTransformationFilter filter(d);
        filter.Put((const byte*)cipher.data(), cipher.size());
        filter.MessageEnd();
        const size_t ret = filter.MaxRetrievable();
        recovered.resize(ret);
        filter.Get((byte*)recovered.data(), recovered.size());
#endif
    }

    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return recover;
}

//--------------------------------------------------------------------------------------------------


int main(int argc, char* argv[])
{

    cout << endl;
    cout << "                         Welcome to Introduction to Cryptography Project\n";
    cout << "                                 Student Name : Lana Qawasmy\n " <<
        "                                  Student ID : 181105\n         " <<
        "                              AES Project\n\n " <<
        "  ***************************************************************************************" << endl;


    Mat cypherImg, recovImg;


    byte key[AES::DEFAULT_KEYLENGTH];//16     //128 bit
    byte iv[AES::BLOCKSIZE];//16          //128 bit
    RC4_Init(key);

    string plain, cipher, recover;
    HexEncoder encoder(new FileSink(cout));

    memset(key, 0x00, sizeof(key));
    memset(iv, 0x00, sizeof(iv));

    Mat image = imread("lena.bmp");
    
    cypherImg = image.clone();
    recovImg = image.clone();

    int rows = image.rows;
    int cols = image.cols;

    

    plain = img2Plain(image); // convert image to string

    int no = plain.length() / 128;    //divide the image into number of 1024 block

    for (int i = 0; i < no; i++)
    {
        vector<byte> rc4K_E = RC4_keyGen(16);
        string tempPlain = "";
        byte key4_E[AES::DEFAULT_KEYLENGTH];
        memset(key4_E, 0x00, sizeof(key));
        copy(rc4K_E.begin(), rc4K_E.end(), key4_E);

        tempPlain = plain.substr(i * 128, 128);

        //------------------------------------------------
        // initializing timer

        auto start = high_resolution_clock::now();

        string encryption = enc(key4_E, iv, tempPlain);

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        Total += (float)duration.count();

        cipher += encryption;

        string decryption = dec(key4_E, iv, encryption);
        recover += decryption;
    }

    string cypherImage;

    for (int i = 0; i < cipher.length(); i++)
    {
        cypherImage += cipher[i];
    }

    Mat recoverc = rec2Img(cypherImage, cypherImg, rows, cols);

    //---------------------------------------------------------------------------------------

    cout << endl << "Execution time for encryption = " << Total * 0.000001 << " Secounds" << endl;

    double ET = (512 * 512 * 3) / (Total * 0.000001);

    cout << "Encryption Throughput = " << ET << endl;

    double NumCycle = (1.5 * 1000000000) / ET;

    cout << "Number of cycles per byte = " << NumCycle << endl;

    //----------------------------------------------------------------------------------------

    Mat reco = rec2Img(recover, recovImg, rows, cols);

    imshow("original image", image);

    imshow("Eecrypted image", recoverc);

    imshow("Restored image", reco);


    imwrite("Eecrypted image.bmp", recoverc);

    imwrite("Restored image.bmp", reco);

    imwrite("original image.bmp", image);

    waitKey(0);

    return 0;
}