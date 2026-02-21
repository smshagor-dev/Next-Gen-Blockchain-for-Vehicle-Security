// OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
// Developer : Md Shahanur Islam Shagor
// Role      : Project Architect & Lead Developer
// SmartCar Blockchain Core - C++ Implementation
// SHA2 + SHA3 Dual-Hash Blockchain for Vehicle Security
// Author: SmartCar Security System
// Public API declarations are mirrored in core/blockchain.h

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <stdexcept>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ========== SHA-256 Implementation ==========
class SHA256 {
private:
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t h[8];
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t sig0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
    static uint32_t sig1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
    static uint32_t ep0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x>>3); }
    static uint32_t ep1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x>>10); }

    void transform() {
        uint32_t m[64], a, b, c, d, e, f, g, hh, t1, t2;
        for(int i=0,j=0; i<16; i++,j+=4)
            m[i] = ((uint32_t)data[j]<<24)|((uint32_t)data[j+1]<<16)|((uint32_t)data[j+2]<<8)|data[j+3];
        for(int i=16; i<64; i++)
            m[i] = ep1(m[i-2]) + m[i-7] + ep0(m[i-15]) + m[i-16];
        a=h[0]; b=h[1]; c=h[2]; d=h[3]; e=h[4]; f=h[5]; g=h[6]; hh=h[7];
        for(int i=0; i<64; i++) {
            t1 = hh + sig1(e) + ch(e,f,g) + K[i] + m[i];
            t2 = sig0(a) + maj(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

public:
    SHA256() { init(); }
    void init() {
        h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
        h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
        datalen = 0; bitlen = 0;
    }
    void update(const uint8_t* d, size_t len) {
        for(size_t i=0; i<len; i++) {
            data[datalen++] = d[i];
            if(datalen==64) { transform(); bitlen+=512; datalen=0; }
        }
    }
    std::string finalize() {
        uint32_t i = datalen;
        data[i++] = 0x80;
        if(datalen < 56) { while(i<56) data[i++]=0; }
        else { while(i<64) data[i++]=0; transform(); memset(data,0,56); }
        bitlen += datalen * 8;
        for(int j=7; j>=0; j--) { data[56+(7-j)] = (bitlen>>(j*8)) & 0xFF; }
        transform();
        std::ostringstream ss;
        for(int j=0; j<8; j++)
            ss << std::hex << std::setw(8) << std::setfill('0') << h[j];
        return ss.str();
    }

    static std::string hash(const std::string& input) {
        SHA256 s;
        s.update(reinterpret_cast<const uint8_t*>(input.c_str()), input.size());
        return s.finalize();
    }
};

// ========== SHA3-256 (Keccak) Implementation ==========
class SHA3_256 {
private:
    static const int RATE = 136; // 1088/8
    static const int CAPACITY = 32;
    uint64_t state[25];
    uint8_t buf[136];
    size_t buflen;

    static const uint64_t RC[24];
    static const int ROT[24];

    void keccak_f() {
        for(int round = 0; round < 24; round++) {
            uint64_t C[5], D[5], B[25];
            // Theta
            for(int x=0;x<5;x++) C[x]=state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20];
            for(int x=0;x<5;x++) D[x]=C[(x+4)%5]^((C[(x+1)%5]<<1)|(C[(x+1)%5]>>63));
            for(int i=0;i<25;i++) state[i]^=D[i%5];
            // Rho & Pi
            int rotat[25]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
            for(int x=0;x<5;x++) for(int y=0;y<5;y++){
                uint64_t v=state[x+5*y]; int r=rotat[x+5*y];
                B[y+5*((2*x+3*y)%5)] = r?((v<<r)|(v>>(64-r))):v;
            }
            // Chi
            for(int x=0;x<5;x++) for(int y=0;y<5;y++)
                state[x+5*y]=B[x+5*y]^(~B[(x+1)%5+5*y]&B[(x+2)%5+5*y]);
            // Iota
            state[0]^=RC[round];
        }
    }

public:
    SHA3_256() { reset(); }
    void reset() { memset(state,0,sizeof(state)); buflen=0; }

    void update(const uint8_t* data, size_t len) {
        for(size_t i=0; i<len; i++) {
            buf[buflen++] = data[i];
            if((int)buflen == RATE) {
                for(int j=0; j<RATE/8; j++) {
                    uint64_t word=0;
                    for(int k=0;k<8;k++) word|=((uint64_t)buf[j*8+k])<<(8*k);
                    state[j]^=word;
                }
                keccak_f();
                buflen=0;
            }
        }
    }

    std::string finalize() {
        memset(buf+buflen, 0, RATE-buflen);
        buf[buflen] = 0x06;
        buf[RATE-1] |= 0x80;
        for(int j=0; j<RATE/8; j++) {
            uint64_t word=0;
            for(int k=0;k<8;k++) word|=((uint64_t)buf[j*8+k])<<(8*k);
            state[j]^=word;
        }
        keccak_f();
        std::ostringstream ss;
        for(int i=0; i<4; i++) {
            for(int k=0;k<8;k++) ss<<std::hex<<std::setw(2)<<std::setfill('0')<<((state[i]>>(8*k))&0xFF);
        }
        return ss.str();
    }

    static std::string hash(const std::string& input) {
        SHA3_256 s; s.reset();
        s.update(reinterpret_cast<const uint8_t*>(input.c_str()), input.size());
        return s.finalize();
    }
};

const uint64_t SHA3_256::RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
const int SHA3_256::ROT[24] = {1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};

// ========== Block Structure ==========
struct TelemetryData {
    double speed;
    double acceleration;
    double fuel_level;
    double battery_voltage;
    double engine_temp;
    double gps_lat;
    double gps_lon;
    double obstacle_distance; // meters
    bool emergency_brake_active;
    std::string timestamp;
};

struct Block {
    int index;
    std::string timestamp;
    std::string vehicle_id;
    std::string telemetry_hash_sha2;
    std::string telemetry_hash_sha3;
    std::string event_hash_sha2;
    std::string event_hash_sha3;
    std::string previous_hash;
    std::string block_hash;    // sha3_256(index+ts+vid+tel_sha3+evt_sha3+prev)
    std::string dual_hash;     // sha2+sha3 combined for extra security
    TelemetryData telemetry;
    std::string event_data;
    bool is_valid;
    bool emergency_brake_triggered;
};

// ========== XOR-based Stream Cipher (simple encryption) ==========
class SimpleEncrypt {
public:
    static std::string encrypt(const std::string& data, const std::string& key) {
        std::string result = data;
        for(size_t i=0; i<data.size(); i++)
            result[i] = data[i] ^ key[i % key.size()];
        // Base64 encode
        static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string enc;
        for(size_t i=0; i<result.size(); i+=3) {
            uint8_t b0=result[i], b1=(i+1<result.size()?result[i+1]:0), b2=(i+2<result.size()?result[i+2]:0);
            enc += table[b0>>2]; enc += table[((b0&3)<<4)|(b1>>4)];
            enc += (i+1<result.size()) ? table[((b1&15)<<2)|(b2>>6)] : '=';
            enc += (i+2<result.size()) ? table[b2&63] : '=';
        }
        return enc;
    }

    static std::string decrypt(const std::string& enc_data, const std::string& key) {
        // Base64 decode
        static const std::string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string decoded;
        for(size_t i=0; i+3<enc_data.size(); i+=4) {
            auto p = [&](char c) { return (uint8_t)table.find(c); };
            uint8_t b0=p(enc_data[i]), b1=p(enc_data[i+1]);
            uint8_t b2=(enc_data[i+2]=='=')?0:p(enc_data[i+2]);
            uint8_t b3=(enc_data[i+3]=='=')?0:p(enc_data[i+3]);
            decoded += (char)((b0<<2)|(b1>>4));
            if(enc_data[i+2]!='=') decoded += (char)(((b1&15)<<4)|(b2>>2));
            if(enc_data[i+3]!='=') decoded += (char)(((b2&3)<<6)|b3);
        }
        std::string result = decoded;
        for(size_t i=0; i<decoded.size(); i++)
            result[i] = decoded[i] ^ key[i % key.size()];
        return result;
    }
};

// ========== Blockchain Manager ==========
class SmartCarBlockchain {
private:
    std::vector<Block> chain;
    std::string vehicle_id;
    std::string encryption_key;
    std::string authorized_hash;  // SHA3-256 of auth token
    bool car_unlocked = false;
    bool engine_started = false;

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream ss;
        ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }

    std::string computeBlockHash(const Block& b) {
        std::string concat = std::to_string(b.index) + b.timestamp + b.vehicle_id +
                             b.telemetry_hash_sha3 + b.event_hash_sha3 + b.previous_hash;
        return SHA3_256::hash(concat);
    }

    std::string computeDualHash(const Block& b) {
        std::string sha2_part = SHA256::hash(b.block_hash);
        std::string sha3_part = SHA3_256::hash(b.block_hash);
        return sha2_part + ":" + sha3_part;
    }

    std::string serializeTelemetry(const TelemetryData& t) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(6);
        ss << t.speed << "," << t.acceleration << "," << t.fuel_level
           << "," << t.battery_voltage << "," << t.engine_temp
           << "," << t.gps_lat << "," << t.gps_lon
           << "," << t.obstacle_distance << "," << t.emergency_brake_active
           << "," << t.timestamp;
        return ss.str();
    }

public:
    SmartCarBlockchain(const std::string& vid, const std::string& enc_key, const std::string& auth_token) {
        vehicle_id = vid;
        encryption_key = enc_key;
        authorized_hash = SHA3_256::hash(auth_token);
        createGenesisBlock();
    }

    void createGenesisBlock() {
        Block genesis;
        genesis.index = 0;
        genesis.timestamp = getCurrentTimestamp();
        genesis.vehicle_id = vehicle_id;
        TelemetryData t0 = {0,0,100,12.6,20,0,0,999,false,genesis.timestamp};
        genesis.telemetry = t0;
        genesis.event_data = "GENESIS:VEHICLE_INITIALIZED";

        std::string tel_str = serializeTelemetry(t0);
        genesis.telemetry_hash_sha2 = SHA256::hash(tel_str);
        genesis.telemetry_hash_sha3 = SHA3_256::hash(tel_str);
        genesis.event_hash_sha2 = SHA256::hash(genesis.event_data);
        genesis.event_hash_sha3 = SHA3_256::hash(genesis.event_data);
        genesis.previous_hash = std::string(64, '0');
        genesis.block_hash = computeBlockHash(genesis);
        genesis.dual_hash = computeDualHash(genesis);
        genesis.is_valid = true;
        genesis.emergency_brake_triggered = false;
        chain.push_back(genesis);
        std::cout << "[BLOCKCHAIN] Genesis block created: " << genesis.block_hash << std::endl;
    }

    bool authenticateUser(const std::string& token) {
        std::string token_hash = SHA3_256::hash(token);
        if(token_hash == authorized_hash) {
            // Verify chain integrity before unlocking
            if(verifyChain()) {
                car_unlocked = true;
                addEvent("AUTH:SUCCESS:USER_AUTHENTICATED");
                std::cout << "[AUTH] Authentication successful. Car UNLOCKED." << std::endl;
                return true;
            } else {
                std::cout << "[AUTH] CHAIN INTEGRITY FAIL - Car remains LOCKED." << std::endl;
                addEvent("AUTH:FAIL:CHAIN_CORRUPTED");
                return false;
            }
        }
        addEvent("AUTH:FAIL:INVALID_TOKEN");
        std::cout << "[AUTH] Authentication FAILED. Invalid credentials." << std::endl;
        return false;
    }

    bool startEngine() {
        if(!car_unlocked) {
            std::cout << "[ENGINE] BLOCKED - Car not authenticated." << std::endl;
            addEvent("ENGINE:BLOCKED:NOT_AUTHENTICATED");
            return false;
        }
        if(!verifyChain()) {
            std::cout << "[ENGINE] BLOCKED - Blockchain integrity compromised!" << std::endl;
            addEvent("ENGINE:BLOCKED:INTEGRITY_FAIL");
            car_unlocked = false;
            return false;
        }
        engine_started = true;
        addEvent("ENGINE:STARTED");
        std::cout << "[ENGINE] Engine STARTED - All systems nominal." << std::endl;
        return true;
    }

    void stopEngine() {
        engine_started = false;
        addEvent("ENGINE:STOPPED");
        std::cout << "[ENGINE] Engine STOPPED." << std::endl;
    }

    void lockCar() {
        car_unlocked = false;
        engine_started = false;
        addEvent("VEHICLE:LOCKED");
        std::cout << "[VEHICLE] Car LOCKED." << std::endl;
    }

    Block addTelemetryBlock(const TelemetryData& telemetry, const std::string& event = "") {
        Block b;
        b.index = chain.size();
        b.timestamp = getCurrentTimestamp();
        b.vehicle_id = vehicle_id;
        b.telemetry = telemetry;
        b.event_data = event.empty() ? "TELEMETRY:UPDATE" : event;

        // Check emergency brake
        b.emergency_brake_triggered = (telemetry.obstacle_distance < 100.0 && engine_started);
        if(b.emergency_brake_triggered) {
            b.event_data = "EMERGENCY:BRAKE_TRIGGERED:OBSTACLE_" + 
                           std::to_string((int)telemetry.obstacle_distance) + "M";
            std::cout << "[EMERGENCY] OBSTACLE DETECTED at " << telemetry.obstacle_distance 
                      << "m! EMERGENCY BRAKE ACTIVATED!" << std::endl;
        }

        std::string tel_str = serializeTelemetry(telemetry);
        b.telemetry_hash_sha2 = SHA256::hash(tel_str);
        b.telemetry_hash_sha3 = SHA3_256::hash(tel_str);
        b.event_hash_sha2 = SHA256::hash(b.event_data);
        b.event_hash_sha3 = SHA3_256::hash(b.event_data);
        b.previous_hash = chain.back().block_hash;
        b.block_hash = computeBlockHash(b);
        b.dual_hash = computeDualHash(b);
        b.is_valid = true;
        chain.push_back(b);
        return b;
    }

    void addEvent(const std::string& event) {
        TelemetryData t = chain.empty() ? TelemetryData{0,0,0,0,0,0,0,999,false,getCurrentTimestamp()} 
                                        : chain.back().telemetry;
        t.timestamp = getCurrentTimestamp();
        addTelemetryBlock(t, event);
    }

    bool verifyChain() {
        for(size_t i=1; i<chain.size(); i++) {
            Block& curr = chain[i];
            Block& prev = chain[i-1];
            // Verify block hash
            if(curr.block_hash != computeBlockHash(curr)) return false;
            // Verify chain linkage
            if(curr.previous_hash != prev.block_hash) return false;
            // Verify telemetry integrity
            std::string tel_str = serializeTelemetry(curr.telemetry);
            if(curr.telemetry_hash_sha3 != SHA3_256::hash(tel_str)) return false;
        }
        return true;
    }

    bool verifyBlockHash(int index) {
        if(index < 0 || index >= (int)chain.size()) return false;
        return chain[index].block_hash == computeBlockHash(chain[index]);
    }

    void saveToFile(const std::string& filename) {
        json j = json::array();
        for(auto& b : chain) {
            json block;
            block["index"] = b.index;
            block["timestamp"] = b.timestamp;
            block["vehicle_id"] = b.vehicle_id;
            block["telemetry_hash_sha2"] = b.telemetry_hash_sha2;
            block["telemetry_hash_sha3"] = b.telemetry_hash_sha3;
            block["event_hash_sha2"] = b.event_hash_sha2;
            block["event_hash_sha3"] = b.event_hash_sha3;
            block["previous_hash"] = b.previous_hash;
            block["block_hash"] = b.block_hash;
            block["dual_hash"] = SimpleEncrypt::encrypt(b.dual_hash, encryption_key);
            block["event_data"] = b.event_data;
            block["telemetry"]["speed"] = b.telemetry.speed;
            block["telemetry"]["acceleration"] = b.telemetry.acceleration;
            block["telemetry"]["fuel_level"] = b.telemetry.fuel_level;
            block["telemetry"]["battery_voltage"] = b.telemetry.battery_voltage;
            block["telemetry"]["engine_temp"] = b.telemetry.engine_temp;
            block["telemetry"]["gps_lat"] = b.telemetry.gps_lat;
            block["telemetry"]["gps_lon"] = b.telemetry.gps_lon;
            block["telemetry"]["obstacle_distance"] = b.telemetry.obstacle_distance;
            block["telemetry"]["emergency_brake_active"] = b.telemetry.emergency_brake_active;
            block["telemetry"]["timestamp"] = b.telemetry.timestamp;
            block["is_valid"] = b.is_valid;
            block["emergency_brake_triggered"] = b.emergency_brake_triggered;
            j.push_back(block);
        }
        std::ofstream f(filename);
        f << j.dump(2);
        std::cout << "[BLOCKCHAIN] Saved " << chain.size() << " blocks to " << filename << std::endl;
    }

    void printChainStatus() {
        std::cout << "\n=== SmartCar Blockchain Status ===" << std::endl;
        std::cout << "Vehicle ID : " << vehicle_id << std::endl;
        std::cout << "Chain Length: " << chain.size() << " blocks" << std::endl;
        std::cout << "Car Locked : " << (car_unlocked ? "NO (UNLOCKED)" : "YES (LOCKED)") << std::endl;
        std::cout << "Engine     : " << (engine_started ? "RUNNING" : "OFF") << std::endl;
        std::cout << "Chain Valid: " << (verifyChain() ? "YES" : "NO - TAMPERED!") << std::endl;
        std::cout << "Latest Hash: " << chain.back().block_hash.substr(0,32) << "..." << std::endl;
        std::cout << "==================================\n" << std::endl;
    }

    size_t getChainLength() const { return chain.size(); }
    bool isCarUnlocked() const { return car_unlocked; }
    bool isEngineStarted() const { return engine_started; }
    const Block& getLatestBlock() const { return chain.back(); }
};

// ========== Main Demo ==========
int main(int argc, char* argv[]) {
    std::cout << "=====================================" << std::endl;
    std::cout << " SmartCar Blockchain Security System" << std::endl;
    std::cout << " SHA2 + SHA3 Dual Hash Chain" << std::endl;
    std::cout << "=====================================" << std::endl;

    std::string vehicle_id = (argc>1) ? argv[1] : "SMARTCAR_VIN_2024_XYZ789";
    std::string enc_key = "SmartCarSecretKey2024!@#SecureXYZ";
    std::string auth_token = (argc>2) ? argv[2] : "SECURE_AUTH_TOKEN_SHA3_2024";

    SmartCarBlockchain blockchain(vehicle_id, enc_key, auth_token);

    // Test 1: Wrong token
    std::cout << "\n[TEST 1] Attempting login with WRONG token..." << std::endl;
    blockchain.authenticateUser("wrong_token");

    // Test 2: Correct token
    std::cout << "\n[TEST 2] Attempting login with CORRECT token..." << std::endl;
    blockchain.authenticateUser(auth_token);

    // Test 3: Start engine
    std::cout << "\n[TEST 3] Starting engine..." << std::endl;
    blockchain.startEngine();

    // Test 4: Normal telemetry
    std::cout << "\n[TEST 4] Adding normal telemetry..." << std::endl;
    TelemetryData t1 = {60.5, 2.3, 85.0, 12.4, 87.0, 23.8103, 90.4125, 500.0, false, ""};
    t1.timestamp = "2024-01-01T10:00:00Z";
    blockchain.addTelemetryBlock(t1, "TELEMETRY:NORMAL_DRIVING");

    // Test 5: Emergency brake scenario
    std::cout << "\n[TEST 5] Emergency brake test (obstacle at 45m)..." << std::endl;
    TelemetryData t2 = {80.0, -5.0, 84.5, 12.3, 92.0, 23.8104, 90.4126, 45.0, true, ""};
    t2.timestamp = "2024-01-01T10:01:00Z";
    blockchain.addTelemetryBlock(t2);

    // Test 6: Verify chain
    std::cout << "\n[TEST 6] Verifying blockchain integrity..." << std::endl;
    bool valid = blockchain.verifyChain();
    std::cout << "Chain integrity: " << (valid ? "VALID" : "COMPROMISED") << std::endl;

    blockchain.printChainStatus();

    // Save to file for Python GUI
    blockchain.saveToFile("/home/claude/smart_car/logs/blockchain.json");

    std::cout << "[DONE] SmartCar blockchain demo complete." << std::endl;
    return 0;
}

