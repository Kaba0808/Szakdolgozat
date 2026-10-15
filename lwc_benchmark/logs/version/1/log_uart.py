import serial
import csv
import time
from datetime import datetime
import os

PORT = "COM3"       # ÍRD ÁT A SAJÁT PORTODRA!
BAUD = 115200

def main():
    print("Csatlakozás a porthoz...")
    try:
        ser = serial.Serial(PORT, BAUD, timeout=1)
    except Exception as e:
        print(f"Hiba a port megnyitásakor: {e}")
        return

    time.sleep(1)
    ser.reset_input_buffer()

    # Automatikus fájlnév generálás az aktuális időpont alapján
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"benchmark_{current_time}.csv"
    
    print(f"Készen állok. Az adatok mentése ide történik: {output_file}")
    print("Most reseteld a panelt (nyomd meg a fekete RESET gombot a kártyán)!")

    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Bővített CSV fejléc
        writer.writerow(["Timestamp", "Algorithm", "Operation", "Size_Bytes", "Cycles", "CPB"])

        while True:
            try:
                line = ser.readline().decode("utf-8", errors="ignore").strip()
                
                if line and "," in line and not line.startswith("==="):
                    parts = line.split(",")
                    
                    # Elvárt formátum a C-től: Algoritmus, Művelet, Méret, Ciklus
                    # Pl: AES-128, Encrypt, 64, 12500
                    if len(parts) == 4:
                        try:
                            alg = parts[0]
                            op = parts[1]
                            size = int(parts[2])
                            cycles = int(parts[3])
                            
                            # CPB számítás (Kulcsgenerálásnál a méret 0, ott nincs CPB)
                            cpb = round(cycles / size, 3) if size > 0 else 0.0
                            
                            final_row = [datetime.now().isoformat(), alg, op, size, cycles, cpb]
                            writer.writerow(final_row)
                            f.flush()
                            
                            print(f"{alg:10} | {op:10} | Méret: {size:4} byte | Ciklus: {cycles:6} | CPB: {cpb:.2f}")
                            
                        except ValueError:
                            pass # Ha hibás adat jön, ugrunk
            
            except KeyboardInterrupt:
                print("\nAdatgyűjtés sikeresen leállítva.")
                break
            except Exception as e:
                print(f"Hiba: {e}")
                break

    ser.close()

if __name__ == '__main__':
    main()