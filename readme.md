## Setting up Virtual Environment
#### Copy all the commands bellow and paste on the terminal
sudo apt update

sudo apt install -y python3 python3-venv python3-dev build-essential

sudo apt install -y libnetfilter-queue-dev

deactivate 2>/dev/null

rm -rf venv

python3 -m venv venv

source venv/bin/activate

python3 -m pip install -U pip wheel setuptools

python3 -m pip install NetfilterQueue

python3 -m pip install flask
python3 -m pip install scapy

python3 --version

python3 -c "import netfilterqueue; print('OK')"

## How to run this program

Have a tiny “checklist” you can follow under stress:
1. Setting up the Virtual Environment
2. Open terminal 1 and run the web.py
3. " " 2 and run the engine.py
4. " " 3 to run enable.sh
5. Clear Logs on the Logs Page
6. Apply Safer preset
7. Run 3 commands (copy from quick test)
8. Show logs filter
9. Apply Professional preset
10. Add two random rules
11. Run 3 commands (copy from quick test)
12. Show logs filtered
13. Disable NFQUEUE by running disable.sh

## Report limitations

Some note to take here is:
1. Userspace NFQUEUE is slower than kernel firewall
2. Running engine needs root/cap_net_admin
3. UI separated from engine for safety
4. Educational/demo only
