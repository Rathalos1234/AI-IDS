# AI-IDS
An IDS application that utilizes both traditional and AI features

# Instructions
To test the code, use these commands:
Batch mode (Capture the network traffic in a batch of the user-defined number of packets and save the output of anomalies into a CSV file):
sudo -E python3 main.py --mode batch --interface {your interface name: e.g., eth0} --count 100 --window-size 100 --contamination 0.1 --n_estimators 100

Real-time mode (Capture the network traffic and output the anomalies to the terminal):
sudo -E python3 main.py --mode real_time --interface {your interface name: e.g., eth0} --window-size 100 --contamination 0.1 --n_estimators 100
