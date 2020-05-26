if [ -z $1 ] || [ -z $2 ]; then
echo "$0 <node_ip> <transfer_over_ftp (true|false)>"  
exit 1
fi


! wget -nc https://github.com/ION28/BLUESPAWN/releases/download/v0.4.4-alpha/BLUESPAWN-client-x64.exe -O ./BLUESPAWN-client-x64.exe
! wget -nc https://github.com/ION28/BLUESPAWN/releases/download/v0.4.4-alpha/BLUESPAWN-client-x86.exe -O ./BLUESPAWN-client-x86.exe
ansible-playbook ./install_bluespawn_windows.yml -i "$1", -e '{"ansible_user":"Admin", "ansible_password":"Admin", "ansible_port":"5986", "ansible_connection":"winrm", "ansible_winrm_server_cert_validation":"ignore", "transfer_over_ftp":"false"}'