#include "pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <algorithm>

using namespace std;

const uint32_t DELTA = 0x9e3779b9;
const uint32_t ROUNDS = 32;

void tea_encrypt(uint32_t* block, const uint32_t* key) {
    uint32_t v0 = block[0];
    uint32_t v1 = block[1];
    uint32_t sum = 0;

    for (uint32_t i = 0; i < ROUNDS; i++) {
        sum += DELTA;
        v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
    }

    block[0] = v0;
    block[1] = v1;
}

void tea_decrypt(uint32_t* block, const uint32_t* key) {
    uint32_t v0 = block[0];
    uint32_t v1 = block[1];
    uint32_t sum = DELTA * ROUNDS;

    for (uint32_t i = 0; i < ROUNDS; i++) {
        v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
        v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        sum -= DELTA;
    }

    block[0] = v0;
    block[1] = v1;
}

void string_to_key(const string& key_str, uint32_t* key) {
    size_t len = key_str.length();
    const char* p = key_str.c_str();
    for (int i = 0; i < 4; i++) {
        key[i] = 0;
        for (int j = 0; j < 4; j++) {
            if (len > 0) {
                key[i] = (key[i] << 8) | static_cast<uint8_t>(*p);
                p++;
                len--;
            }
        }
    }
}

void add_padding(vector<uint8_t>& data) {
    uint8_t pad_value = 8 - (data.size() % 8);
    data.insert(data.end(), pad_value, pad_value);
}

bool remove_padding(vector<uint8_t>& data) {
    if (data.empty()) return false;
    uint8_t pad_value = data.back();
    if (pad_value > 8 || pad_value == 0) return false;
    for (size_t i = data.size() - pad_value; i < data.size(); i++) {
        if (data[i] != pad_value) return false;
    }
    data.resize(data.size() - pad_value);
    return true;
}

void process_file(const string& input_file, const string& output_file,
    const uint32_t* key, bool encrypt) {
    ifstream in(input_file, ios::binary);
    ofstream out(output_file, ios::binary);

    if (!in || !out) {
        throw runtime_error("Ошибка открытия файла");
    }

    vector<uint8_t> data(
        (istreambuf_iterator<char>(in)),
        (istreambuf_iterator<char>())
    );

    if (encrypt && !data.empty()) {
        add_padding(data);
    }

    for (size_t i = 0; i < data.size(); i += 8) {
        uint32_t block[2] = { 0, 0 };

        for (int j = 0; j < 8; j++) {
            if (i + j < data.size()) {
                if (j < 4) block[0] |= data[i + j] << (24 - j * 8);
                else block[1] |= data[i + j] << (56 - j * 8);
            }
        }

        if (encrypt) tea_encrypt(block, key);
        else tea_decrypt(block, key);

        for (int j = 0; j < 4; j++) {
            out.put(static_cast<char>(block[0] >> (24 - j * 8)) & 0xFF);
        }
        for (int j = 0; j < 4; j++) {
            out.put(static_cast<char>(block[1] >> (24 - j * 8)) & 0xFF);
        }
    }

    if (!encrypt && !data.empty()) {
        vector<uint8_t> out_data;
        out.close();
        ifstream check(output_file, ios::binary);
        out_data.assign(
            istreambuf_iterator<char>(check),
            istreambuf_iterator<char>()
        );
        if (!remove_padding(out_data)) {
            cerr << "Ошибка удаления padding. Возможно неверный ключ." << endl;
        }
        ofstream fix(output_file, ios::binary);
        fix.write(reinterpret_cast<const char*>(out_data.data()), out_data.size());
    }
}

int main(int argc, char* argv[]) {
    setlocale(LC_CTYPE, "rus");
    if (argc != 5) {
        cout << "=== (с) Жиляев Максим. ААМ-24 ===" << endl;
        cerr << "Использование:\n"
            << "Шифрование: " << argv[0] << " -e <ключ> <входной_файл> <выходной_файл>\n"
            << "Дешифрование: " << argv[0] << " -d <ключ> <входной_файл> <выходной_файл>\n";
        return 1;
    }

    try {
        string mode = argv[1];
        string key_str = argv[2];
        string input_file = argv[3];
        string output_file = argv[4];

        if (key_str.length() < 16) {
            cerr << "Ключ должен быть не менее 16 символов.\n";
            return 1;
        }

        uint32_t key[4];
        string_to_key(key_str, key);

        if (mode == "-e") {
            process_file(input_file, output_file, key, true);
            cout << "Файл зашифрован успешно.\n";
        }
        else if (mode == "-d") {
            process_file(input_file, output_file, key, false);
            cout << "Файл расшифрован успешно.\n";
        }
        else {
            cerr << "Неверный режим. Используйте -e или -d.\n";
            return 1;
        }
    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}