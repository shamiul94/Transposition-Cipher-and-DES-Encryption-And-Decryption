
#include "DES.h"

#define LEFT_32  0b1111111111111111111111111111111100000000000000000000000000000000
#define RIGHT_32 0b0000000000000000000000000000000011111111111111111111111111111111
#define LEFT_28  0b0000000011111111111111111111111111110000000000000000000000000000
#define RIGHT_28 0b0000000000000000000000000000000000001111111111111111111111111111
#define LAST_8   0b0000000000000000000000000000000000000000000000000000000011111111

string key, plainText, ciphered = "", curr_real_data = "", final_ciphered = "", final_real_data = "";
ll currPlainTextIndex = 0, currenntCipheredTextIndex = 0;
ll initialTransposedDataLL;
ll initialKeyLL, initialTransposedKeyLL;

vector<ll> KiArr;

string CIPHERED;

void makePlainTextFactorOf8() {
    if (plainText.length() % 8 != 0) {
        ll rem = static_cast<unsigned long long int>((plainText.length() % 8));
        ll remaining = 8 - rem;
        for (ll i = 0; i < remaining; i++) {
            plainText = plainText + '-';
        }
    }
}


string getNextPlainTextBlock() {
    if (currPlainTextIndex >= plainText.length()) {
        return "";
    }
    string s;
    s = plainText.substr(static_cast<unsigned long>(currPlainTextIndex), 8);
    currPlainTextIndex += 8;
    return s;
}


string getNextCipherBlock() {
    if (currenntCipheredTextIndex >= CIPHERED.length()) {
        return "";
    }
    string s;
    s = CIPHERED.substr(static_cast<unsigned long>(currenntCipheredTextIndex), 8);
    currenntCipheredTextIndex += 8;
    return s;
}


ll stringTo64BitBlock(string s) {
    ll bitBlock = 0;
    for (ll i = 0; i < s.length(); i++) {
        char ch = s[i];
        ll a = (ll) ch;
        bitBlock <<= 8;
        bitBlock |= a;
    }
    return bitBlock;
}


ll Iteration(ll data, ll k) {
    ll input = data;
    ll key = k;

    ll prevLeft_32, prevRight_32, newLeft_32, newRight_32;
    ll keyLeft28 = 0, keyRight28 = 0, msb;
    KiArr.clear();

    for (ll i = 0; i < 16; i++) {
        prevLeft_32 = input & (ll) LEFT_32;
        prevLeft_32 >>= 32;
        prevRight_32 = input & (ll) RIGHT_32;

        newLeft_32 = prevRight_32;

        ll shiftTimes = SHIFT[i];

        keyLeft28 = key & (ll) LEFT_28;
        keyRight28 = key & (ll) RIGHT_28;

        for (ll j = 0; j < shiftTimes; j++) {

            keyLeft28 >>= 28;
            msb = check(keyLeft28, 27);
            keyLeft28 = reset(keyLeft28, 27);
            keyLeft28 <<= 1;
            keyLeft28 |= msb;
            keyLeft28 <<= 28;


            msb = check(keyRight28, 27);
            keyRight28 = reset(keyRight28, 27);
            keyRight28 <<= 1;
            keyRight28 |= msb;
        }

        ll rotatedKey = keyLeft28 | keyRight28; // 56 bits

        key = rotatedKey; // 56 bits

        ll Ki = 0;
        for (ll j = 0; j < 48; j++) {
            ll idx = CP_2[j];
            idx--;
            Ki = setValueBit(Ki, j, check(rotatedKey, idx));
        }

        KiArr.push_back(Ki);



        ///////////////// function ////////////////////////

        ll e = 0;
        for (ll j = 0; j < 48; j++) {
            ll idx = E[j];
            idx--;
            e = setValueBit(e, j, check(prevRight_32, idx));
        }

        ll func = e ^Ki;

        ll transposedFuncLL = 0;

        for (ll j = 0; j < 32; j++) {
            ll idx = PI_2[j];
            idx--;
            transposedFuncLL = setValueBit(transposedFuncLL, j, check(func, idx)); // 32 bits
        }

        ll PboxTransposeLL = 0;
        for (ll j = 0; j < 32; j++) {
            ll idx = P[j];
            idx--;
            PboxTransposeLL = setValueBit(PboxTransposeLL, j, check(transposedFuncLL, idx)); // 32 bits
        }


        /////////////////////after getting Ki and function value/////////////////////////

        newRight_32 = prevLeft_32 ^ PboxTransposeLL; // 32 bits

        newLeft_32 <<= 32;
        input = newLeft_32 | newRight_32; // 64 bits
    }

    ll final_output = input;

    ll temLeft32, temRight32;

    temLeft32 = final_output & (ll) LEFT_32;
    temRight32 = final_output & (ll) RIGHT_32;

    temLeft32 >>= 32;
    temRight32 <<= 32;

    final_output = temLeft32 | temRight32;

    ll finalTransposeLL = 0;
    for (ll j = 0; j < 64; j++) {
        ll idx = PI_1[j];
        idx--;
        finalTransposeLL = setValueBit(finalTransposeLL, j, check(final_output, idx)); // 64 bits
    }

    final_output = finalTransposeLL;
    return final_output;
}


string DESencryption() {

    initialKeyLL = stringTo64BitBlock(key);
    makePlainTextFactorOf8();

    string nextPlainTextBlock = getNextPlainTextBlock(); /// guti
    while (!nextPlainTextBlock.empty()) {
        ll nextBitBlock = stringTo64BitBlock(nextPlainTextBlock);

        initialTransposedDataLL = 0;

        for (ll i = 0; i < 64; i++) {
            ll idx = PI[i];
            idx--;
            initialTransposedDataLL = setValueBit(initialTransposedDataLL, i, check(nextBitBlock, idx));
        }

        initialTransposedKeyLL = 0;
        for (ll i = 0; i < 56; i++) {
            ll idx = CP_1[i];
            idx--;
            initialTransposedKeyLL = setValueBit(initialTransposedKeyLL, i, check(initialKeyLL, idx)); // 56 bits
        }


        ll ans = Iteration(initialTransposedDataLL, initialTransposedKeyLL);
//        cout << fromLLToBinaryString(ans) << endl ;

        ciphered = "";
        for (ll t = 0; t < 8; t++) {


            ll last8bits = ans & (ll) LAST_8;
            ans >>= 8;
            char c = (char) ((int) last8bits);
            ciphered += c;
        }

        reverse(ciphered.begin(), ciphered.end());

        final_ciphered = final_ciphered + ciphered;
        //////////////////////////////////////////////////
        nextPlainTextBlock = getNextPlainTextBlock();
    }
    cout << final_ciphered << endl;
    return final_ciphered;
}


ll Iteration2(ll data, ll k) {
    ll input = data;

    ll key = k;

    ll prevLeft_32, prevRight_32, newLeft_32, newRight_32;
    ll keyLeft28 = 0, keyRight28 = 0, msb;

    for (int i = 15; i >= 0; i--) {

        prevLeft_32 = input & (ll) LEFT_32;
        prevLeft_32 >>= 32;
        prevRight_32 = input & (ll) RIGHT_32;


        newLeft_32 = prevRight_32;

        ll Ki = KiArr[i];

        ///////////////// function ////////////////////////

        ll e = 0;
        for (ll j = 0; j < 48; j++) {
            ll idx = E[j];
            idx--;
            e = setValueBit(e, j, check(prevRight_32, idx));
        }

        ll func = e ^Ki;

        ll transposedFuncLL = 0;

        for (ll j = 0; j < 32; j++) {
            ll idx = PI_2[j];
            idx--;
            transposedFuncLL = setValueBit(transposedFuncLL, j, check(func, idx)); // 32 bits
        }


        ll PboxTransposeLL = 0;
        for (ll j = 0; j < 32; j++) {
            ll idx = P[j];
            idx--;
            PboxTransposeLL = setValueBit(PboxTransposeLL, j, check(transposedFuncLL, idx)); // 32 bits
        }

        /////////////////////after getting Ki and function value/////////////////////////

        newRight_32 = prevLeft_32 ^ PboxTransposeLL; // 32 bits

        newLeft_32 <<= 32;
        input = newLeft_32 | newRight_32; // 64 bits
    }


    ll final_output = input;

    ll temLeft32, temRight32;

    temLeft32 = final_output & (ll) LEFT_32;
    temRight32 = final_output & (ll) RIGHT_32;

    temLeft32 >>= 32;
    temRight32 <<= 32;

    final_output = temLeft32 | temRight32;

    ll finalTransposeLL = 0;
    for (ll j = 0; j < 64; j++) {
        ll idx = PI_1[j];
        idx--;
        finalTransposeLL = setValueBit(finalTransposeLL, j, check(final_output, idx)); // 64 bits
    }

    final_output = finalTransposeLL;


    return final_output;
}


string DESdecryption() {

    initialKeyLL = stringTo64BitBlock(key);
//    makePlainTextFactorOf8();

    string nextCipherBlock = getNextCipherBlock(); /// guti
    while (!nextCipherBlock.empty()) {
        ll nextBitBlock = stringTo64BitBlock(nextCipherBlock);

        initialTransposedDataLL = 0;

        for (ll i = 0; i < 64; i++) {
            ll idx = PI[i];
            idx--;
            initialTransposedDataLL = setValueBit(initialTransposedDataLL, i, check(nextBitBlock, idx));
        }

        initialTransposedKeyLL = 0;
        for (ll i = 0; i < 56; i++) {
            ll idx = CP_1[i];
            idx--;
            initialTransposedKeyLL = setValueBit(initialTransposedKeyLL, i, check(initialKeyLL, idx)); // 56 bits
        }


        ll ans = Iteration2(initialTransposedDataLL, initialTransposedKeyLL);


        curr_real_data = "";
        for (ll t = 0; t < 8; t++) {
            ll last8bits = ans & (ll) LAST_8;
            ans >>= 8;
            char c = (char) ((int) last8bits);
            curr_real_data += c;
        }

        reverse(curr_real_data.begin(), curr_real_data.end());

        final_real_data += curr_real_data;

        //////////////////////////////////////////////////
        nextCipherBlock = getNextCipherBlock();
    }
    cout << final_real_data << endl;
    return final_real_data;
}


int main() {
    fi;
    fo;
    getline(cin, key);
    getline(cin, plainText);

    CIPHERED = DESencryption();

    DESdecryption();

    return 0;
}