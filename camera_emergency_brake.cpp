// OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
// Developer : Md Shahanur Islam Shagor
// Role      : Project Architect & Lead Developer
// SmartCar Camera Emergency Brake (C++ / OpenCV)
// Detects front obstacles using camera and triggers emergency brake if distance is below threshold.
//
// Build (Linux/macOS):
//   g++ -std=c++17 -O2 core/camera_emergency_brake.cpp -o build/camera_emergency_brake `pkg-config --cflags --libs opencv4`
//
// Run:
//   ./build/camera_emergency_brake 0 8.0
//     arg1: camera index (default 0)
//     arg2: emergency distance meters (default 8.0)

#include <opencv2/opencv.hpp>
#include <opencv2/objdetect.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>

struct DetectedObject {
    cv::Rect box;
    std::string label;
    double confidence;
    double estimated_distance_m;
};

class DistanceEstimator {
private:
    // Approximate focal length in pixels for a 720p-ish webcam.
    // For accurate results, calibrate with known target distance/size.
    double focal_length_px = 850.0;

public:
    double estimateDistanceMeters(double real_height_m, int box_height_px) const {
        if (box_height_px <= 0) return 999.0;
        return (real_height_m * focal_length_px) / static_cast<double>(box_height_px);
    }
};

class CameraEmergencyBrake {
private:
    cv::VideoCapture cap;
    cv::HOGDescriptor hog;
    DistanceEstimator dist_estimator;
    double emergency_distance_m;
    std::string log_path = "logs/camera_emergency_events.jsonl";
    bool brake_active = false;

    void logEvent(const std::string& type, const DetectedObject& obj) {
        std::ofstream out(log_path, std::ios::app);
        if (!out.is_open()) return;

        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        gmtime_s(&tm, &tt);
#else
        gmtime_r(&tt, &tm);
#endif
        std::ostringstream ts;
        ts << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");

        out << "{"
            << "\"timestamp\":\"" << ts.str() << "\","
            << "\"event\":\"" << type << "\","
            << "\"label\":\"" << obj.label << "\","
            << "\"distance_m\":" << std::fixed << std::setprecision(2) << obj.estimated_distance_m << ","
            << "\"confidence\":" << std::fixed << std::setprecision(2) << obj.confidence << ","
            << "\"x\":" << obj.box.x << ","
            << "\"y\":" << obj.box.y << ","
            << "\"w\":" << obj.box.width << ","
            << "\"h\":" << obj.box.height
            << "}\n";
    }

    std::vector<DetectedObject> detectPedestrians(const cv::Mat& frame) {
        std::vector<cv::Rect> boxes;
        std::vector<double> weights;
        std::vector<DetectedObject> out;

        hog.detectMultiScale(
            frame, boxes, weights,
            0.0, cv::Size(8, 8), cv::Size(16, 16),
            1.05, 2.0, false
        );

        for (size_t i = 0; i < boxes.size(); ++i) {
            DetectedObject obj;
            obj.box = boxes[i];
            obj.label = "person";
            obj.confidence = (i < weights.size()) ? weights[i] : 0.5;
            obj.estimated_distance_m = dist_estimator.estimateDistanceMeters(1.70, obj.box.height);
            out.push_back(obj);
        }
        return out;
    }

    std::vector<DetectedObject> detectGenericObstacles(const cv::Mat& frame) {
        // Lane-centered contour-based detection fallback for cars/objects.
        cv::Mat gray, blur, edges;
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
        cv::GaussianBlur(gray, blur, cv::Size(5, 5), 0);
        cv::Canny(blur, edges, 60, 180);

        std::vector<std::vector<cv::Point>> contours;
        cv::findContours(edges, contours, cv::RETR_EXTERNAL, cv::CHAIN_APPROX_SIMPLE);

        const int frame_w = frame.cols;
        const int frame_h = frame.rows;
        const int roi_top = static_cast<int>(frame_h * 0.35);
        const int roi_left = static_cast<int>(frame_w * 0.20);
        const int roi_right = static_cast<int>(frame_w * 0.80);

        std::vector<DetectedObject> out;
        for (const auto& c : contours) {
            cv::Rect r = cv::boundingRect(c);
            double area = cv::contourArea(c);
            if (area < 1800.0) continue;
            if (r.y < roi_top) continue;

            int cx = r.x + r.width / 2;
            if (cx < roi_left || cx > roi_right) continue;

            DetectedObject obj;
            obj.box = r;
            obj.label = "obstacle";
            obj.confidence = std::min(0.99, area / 20000.0);
            obj.estimated_distance_m = dist_estimator.estimateDistanceMeters(1.50, r.height);
            out.push_back(obj);
        }
        return out;
    }

    void drawOverlay(cv::Mat& frame, const std::vector<DetectedObject>& objects, double fps) {
        for (const auto& obj : objects) {
            cv::Scalar color = (obj.estimated_distance_m < emergency_distance_m) ? cv::Scalar(0, 0, 255)
                                                                                 : cv::Scalar(0, 255, 0);
            cv::rectangle(frame, obj.box, color, 2);
            std::ostringstream txt;
            txt << obj.label << " " << std::fixed << std::setprecision(1) << obj.estimated_distance_m << "m";
            cv::putText(frame, txt.str(), cv::Point(obj.box.x, std::max(20, obj.box.y - 8)),
                        cv::FONT_HERSHEY_SIMPLEX, 0.55, color, 2);
        }

        cv::Scalar status_color = brake_active ? cv::Scalar(0, 0, 255) : cv::Scalar(0, 220, 0);
        std::string status = brake_active ? "EMERGENCY BRAKE: ACTIVE" : "EMERGENCY BRAKE: STANDBY";
        cv::putText(frame, status, cv::Point(20, 35), cv::FONT_HERSHEY_SIMPLEX, 0.8, status_color, 2);

        std::ostringstream fps_text;
        fps_text << "FPS: " << std::fixed << std::setprecision(1) << fps
                 << " | Threshold: " << std::fixed << std::setprecision(1) << emergency_distance_m << "m";
        cv::putText(frame, fps_text.str(), cv::Point(20, 65), cv::FONT_HERSHEY_SIMPLEX, 0.6, cv::Scalar(255, 255, 0), 2);
    }

public:
    CameraEmergencyBrake(int camera_index, double emergency_distance)
        : emergency_distance_m(emergency_distance) {
        cap.open(camera_index);
        if (!cap.isOpened()) {
            throw std::runtime_error("Failed to open camera device.");
        }
        hog.setSVMDetector(cv::HOGDescriptor::getDefaultPeopleDetector());
    }

    void run() {
        std::cout << "[CAMERA] Started. Press 'q' to quit.\n";
        std::cout << "[BRAKE] Emergency threshold: " << emergency_distance_m << " meters\n";

        auto t_prev = std::chrono::high_resolution_clock::now();
        double fps = 0.0;

        while (true) {
            cv::Mat frame;
            cap >> frame;
            if (frame.empty()) break;

            std::vector<DetectedObject> objs = detectPedestrians(frame);
            std::vector<DetectedObject> generic = detectGenericObstacles(frame);
            objs.insert(objs.end(), generic.begin(), generic.end());

            brake_active = false;
            DetectedObject closest{};
            closest.estimated_distance_m = 999.0;

            for (const auto& o : objs) {
                if (o.estimated_distance_m < closest.estimated_distance_m) {
                    closest = o;
                }
            }

            if (!objs.empty() && closest.estimated_distance_m < emergency_distance_m) {
                brake_active = true;
                std::cout << "[EMERGENCY] Object=" << closest.label
                          << " distance=" << std::fixed << std::setprecision(2)
                          << closest.estimated_distance_m << "m -> BRAKE\n";
                logEvent("EMERGENCY_BRAKE_TRIGGERED", closest);
            }

            auto t_now = std::chrono::high_resolution_clock::now();
            double dt = std::chrono::duration<double>(t_now - t_prev).count();
            if (dt > 0) fps = 1.0 / dt;
            t_prev = t_now;

            drawOverlay(frame, objs, fps);
            cv::imshow("SmartCar Camera Emergency Brake", frame);

            char key = static_cast<char>(cv::waitKey(1));
            if (key == 'q' || key == 'Q') break;
        }
    }
};

int main(int argc, char** argv) {
    int camera_index = 0;
    double threshold_m = 8.0;
    if (argc > 1) camera_index = std::stoi(argv[1]);
    if (argc > 2) threshold_m = std::stod(argv[2]);

    try {
        CameraEmergencyBrake app(camera_index, threshold_m);
        app.run();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

