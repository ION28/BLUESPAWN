#!/bin/bash
# requires jq be installed on the system

set -ex

usage() {
    echo "Usage:";
    echo "$0 -i <node_ip> -u <node_user> -p <node_password> -t <transfer_over_ftp|bool>";
    echo "$0 -h";
}

deploy() {
    i_flag=false
    u_flag=false
    p_flag=false
    t_flag=false

    while getopts ":hi:u:p:t:" opt; do
        case "$opt" in
            h) usage; exit 1;;
            i) i_flag=true; ip=$OPTARG;;
            u) u_flag=true; user=$OPTARG;;
            p) p_flag=true; pass=$OPTARG;;
            t) t_flag=true; transfer_over_ftp=$OPTARG;;
            \?) echo "Unknown option: -$OPTARG" >&2; exit 1;;
            :) echo "Missing option argument for -$OPTARG" >&2; exit 1;;
            *) echo "Unimplemented option: -$OPTARG" >&2; exit 1;;
        esac
    done

    if ! $i_flag 
    then
        echo "You must specify a target IP" >&2
        exit 1
    fi

    if ! $u_flag 
    then
        echo "You must specify a node username" >&2
        exit 1
    fi

    if ! $p_flag 
    then
        echo "You must specify a node password" >&2
        exit 1
    fi

    if ! $t_flag 
    then
        transfer_over_ftp=false
    fi

    shift "$(($OPTIND -1))"
    
    ! curl -f https://github.com/ION28/BLUESPAWN/releases/download/v0.4.4-alpha/BLUESPAWN-client-x64.exe -o BLUESPAWN-client-x64.exe
    ! curl -f https://github.com/ION28/BLUESPAWN/releases/download/v0.4.4-alpha/BLUESPAWN-client-x86.exe -o BLUESPAWN-client-x86.exe
    
    exists64bin=false
    exists86bin=false
    test -f ./BLUESPAWN-client-x64.exe && exists64bin=true
    test -f ./BLUESPAWN-client-x86.exe && exists86bin=true

    extra_vars=$( jq -n \
                    --arg user "$user" \
                    --arg pass "$pass" \
                    --arg transfer_over_ftp "$transfer_over_ftp" \
                    --arg exists64bin "$exists64bin" \
                    --arg exists86bin "$exists86bin" \
                    '{"ansible_user": $user, "ansible_password": $pass, "ansible_port":"5986", "ansible_connection":"winrm", "ansible_winrm_server_cert_validation":"ignore", "transfer_over_ftp": $transfer_over_ftp, "exists64bin": $exists64bin, "exists86bin": $exists86bin}' )

    ansible-playbook ./install_bluespawn_windows.yml -i "$ip", -e "$extra_vars" -vv
}

deploy "$@"

exit
