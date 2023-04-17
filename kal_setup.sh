sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf -y

sudo apt install python3-venv -y
python3 -m pip install --user pipx
python3 -m pipx ensurepath

pipx install git+https://github.com/Tib3rius/AutoRecon.git



sudo apt-get install wget gpg -y
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
rm -f packages.microsoft.gpg

sudo apt install apt-transport-https
sudo apt update
sudo apt install code

sudo apt install tmux
sudo apt install rlwrap

echo "set -g prefix C-a" >> ~/.tmux.conf
echo "bind C-a send-prefix" >> ~/.tmux.conf
echo "unbind C-b" >> ~/.tmux.conf
echo alias sudo="sudo env "PATH=$PATH"" >> ~/.zshrc
