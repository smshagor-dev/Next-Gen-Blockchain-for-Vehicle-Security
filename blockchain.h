// OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
// Developer : Md Shahanur Islam Shagor
// Role      : Project Architect & Lead Developer
#ifndef SMARTCAR_BLOCKCHAIN_H
#define SMARTCAR_BLOCKCHAIN_H

#include <string>
#include <vector>

struct TelemetryData {
    double speed;
    double acceleration;
    double fuel_level;
    double battery_voltage;
    double engine_temp;
    double gps_lat;
    double gps_lon;
    double obstacle_distance;
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
    std::string block_hash;
    std::string dual_hash;
    TelemetryData telemetry;
    std::string event_data;
    bool is_valid;
    bool emergency_brake_triggered;
};

class SmartCarBlockchain {
private:
    std::vector<Block> chain;
    std::string vehicle_id;
    std::string encryption_key;
    std::string authorized_hash;
    bool car_unlocked = false;
    bool engine_started = false;

    std::string getCurrentTimestamp();
    std::string computeBlockHash(const Block& b);
    std::string computeDualHash(const Block& b);
    std::string serializeTelemetry(const TelemetryData& t);

public:
    SmartCarBlockchain(const std::string& vid, const std::string& enc_key, const std::string& auth_token);

    void createGenesisBlock();
    bool authenticateUser(const std::string& token);
    bool startEngine();
    void stopEngine();
    void lockCar();
    Block addTelemetryBlock(const TelemetryData& telemetry, const std::string& event = "");
    void addEvent(const std::string& event);
    bool verifyChain();
    bool verifyBlockHash(int index);
    void saveToFile(const std::string& filename);
    void printChainStatus();

    size_t getChainLength() const;
    bool isCarUnlocked() const;
    bool isEngineStarted() const;
    const Block& getLatestBlock() const;
};

#endif

