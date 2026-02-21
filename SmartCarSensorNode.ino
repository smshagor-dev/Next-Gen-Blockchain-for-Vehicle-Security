// OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
// Developer : Md Shahanur Islam Shagor
// Role      : Project Architect & Lead Developer
/*
  SmartCar Arduino Sensor Node
  Streams JSON telemetry over Serial (115200).

  Suggested wiring:
  - HC-SR04 TRIG -> D7
  - HC-SR04 ECHO -> D6
  - Potentiometer (speed simulation) -> A0
  - LM35/NTC (temp simulation input) -> A1
*/

const int TRIG_PIN = 7;
const int ECHO_PIN = 6;
const int SPEED_PIN = A0;
const int TEMP_PIN = A1;

unsigned long lastSendMs = 0;
float odometerKm = 0.0;

float readDistanceM() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  long duration = pulseIn(ECHO_PIN, HIGH, 30000UL);
  if (duration <= 0) return 999.0;
  float distanceCm = duration * 0.0343 / 2.0;
  if (distanceCm < 2.0) distanceCm = 2.0;
  if (distanceCm > 99900.0) distanceCm = 99900.0;
  return distanceCm / 100.0;
}

void setup() {
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  Serial.begin(115200);
}

void loop() {
  unsigned long now = millis();
  if (now - lastSendMs < 200) return;
  float dtSec = (now - lastSendMs) / 1000.0;
  if (lastSendMs == 0) dtSec = 0.2;
  lastSendMs = now;

  int speedRaw = analogRead(SPEED_PIN);
  int tempRaw = analogRead(TEMP_PIN);

  float speedKmh = (speedRaw / 1023.0) * 120.0;
  float tempC = 20.0 + (tempRaw / 1023.0) * 90.0;
  float distanceM = readDistanceM();
  bool emergency = distanceM < 100.0;
  float rpm = 900.0 + speedKmh * 45.0;
  odometerKm += speedKmh / 3600.0 * dtSec;

  Serial.print("{");
  Serial.print("\"source\":\"arduino\",");
  Serial.print("\"speed\":"); Serial.print(speedKmh, 2); Serial.print(",");
  Serial.print("\"acceleration\":0.0,");
  Serial.print("\"fuel_level\":80.0,");
  Serial.print("\"battery_voltage\":12.40,");
  Serial.print("\"engine_temp\":"); Serial.print(tempC, 2); Serial.print(",");
  Serial.print("\"gps_lat\":23.810300,");
  Serial.print("\"gps_lon\":90.412500,");
  Serial.print("\"obstacle_distance\":"); Serial.print(distanceM, 2); Serial.print(",");
  Serial.print("\"emergency_brake_active\":"); Serial.print(emergency ? "true" : "false"); Serial.print(",");
  Serial.print("\"steering_angle\":0.0,");
  Serial.print("\"brake_pressure\":"); Serial.print(emergency ? 100.0 : 0.0, 1); Serial.print(",");
  Serial.print("\"throttle_position\":"); Serial.print((speedKmh / 120.0) * 100.0, 1); Serial.print(",");
  Serial.print("\"rpm\":"); Serial.print(rpm, 1); Serial.print(",");
  Serial.print("\"odometer\":"); Serial.print(odometerKm, 5); Serial.print(",");
  Serial.print("\"event\":\"HW:ARDUINO:TELEMETRY\"");
  Serial.println("}");
}

