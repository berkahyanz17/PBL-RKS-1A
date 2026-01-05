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

## Demo script (1 page)

Have a tiny “demo checklist” you can follow under stress:
1. Apply Safer preset
2. Run 3 commands
3. Show logs filter
4. Apply Professional preset
5. Run 3 commands
6. Show logs filtered
7. Disable NFQUEUE

## Report limitations

Make sure you can say/write:
1. Userspace NFQUEUE is slower than kernel firewall
2. Running engine needs root/cap_net_admin
3. UI separated from engine for safety
4. Educational/demo only
