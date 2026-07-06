import serial
import csv
import time
from datetime import datetime

PORT = "COM3"
BAUD = 115200
OUTPUT_FILE = "benchmark_results.csv"

print("Csatlakozás a porthoz, várakozás a board resetjére...")
ser = serial.Serial(PORT, BAUD, timeout=1)
time.sleep(1)          # rövid várakozás, amíg a port stabilizálódik
ser.reset_input_buffer()  # korábbi, elavult adatok törlése a bufferből

print("Készen állok. Most reseteld a panelt (nyomd meg a RESET gombot)!")

with open(OUTPUT_FILE, mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "algorithm", "operation", "cycles", "cpb"])

    while True:
        try:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if line and "," in line and not line.startswith("==="):
                parts = line.split(",")
                if len(parts) == 4:
                    writer.writerow([datetime.now().isoformat()] + parts)
                    f.flush()
                    print(line)
        except KeyboardInterrupt:
            print("Leállítva.")
            break

ser.close()