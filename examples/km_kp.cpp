#include "EVI/KeyGenerator.hpp"
#include "km/KeyManager.hpp"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc, char **argv) {

    evi::ParameterPreset preset = evi::ParameterPreset::IP0;
    std::vector<evi::Context> contexts = makeMultiContext(preset, evi::DeviceType::CPU, evi::EvalMode::RMP);
    evi::SealInfo s_info(evi::SealMode::NONE);
    evi::MultiKeyGenerator keygen(contexts, "keys", s_info);

    std::stringstream sec_ss;
    std::stringstream enc_ss;
    std::stringstream eval_ss;
    keygen.generateKeys(sec_ss, enc_ss, eval_ss);
    sec_ss.seekg(0);
    enc_ss.seekg(0);
    eval_ss.seekg(0);

    std::stringstream w_sec_ss;
    std::stringstream w_enc_ss;
    std::stringstream w_eval_ss;

    const std::string key_id = "CL:envector:demo:vector_sk:apne2";

    evi::KeyManager manager = evi::makeKeyManager();
    manager.wrapSecKey(key_id, sec_ss, w_sec_ss);
    manager.wrapEncKey(key_id, enc_ss, w_enc_ss);
    manager.wrapEvalKey(key_id, eval_ss, w_eval_ss);

    std::cout << "All keys wrapped" << std::endl;

    std::stringstream uw_sec_ss;
    std::stringstream uw_enc_ss;
    std::stringstream uw_eval_ss;

    w_sec_ss.seekg(0);
    w_enc_ss.seekg(0);
    w_eval_ss.seekg(0);

    manager.unwrapSecKey(w_sec_ss, uw_sec_ss);
    manager.unwrapEncKey(w_enc_ss, uw_enc_ss);
    manager.unwrapEvalKey(w_eval_ss, uw_eval_ss);

    std::ofstream sec_plain("keys/seckey_unwraped.bin", std::ios::binary);
    std::ofstream enc_plain("keys/enckey_unwraped.bin", std::ios::binary);
    std::ofstream eval_plain("keys/evalkey_unwraped.bin", std::ios::binary);
    sec_plain << uw_sec_ss.rdbuf();
    enc_plain << uw_enc_ss.rdbuf();
    eval_plain << uw_eval_ss.rdbuf();

    return 0;
}
