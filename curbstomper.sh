#!bin/bash

#turn on firewall
sudo ufw enable
#auto updates
dpkg-reconfigure --priority=low unattended-upgrades 
# remove netcat (a backdoor to machine)
sudo apt-get autoremove --purge -y netcat-traditional
sudo apt-get autoremove --purge -y netcat-openbsd
sudo apt-get autoremove --purge -y netcat6
sudo apt-get autoremove --purge -y netcat


#delete media files
find . -iname "*.mp2" ! -path "*/run/*" -delete
find . -iname "*.mp3" ! -path "*/run/*" -delete
find . -iname "*.mp4" ! -path "*/run/*" -delete
find . -iname "*.mpg" ! -path "*/run/*" -delete
find . -iname "*.mpeg" ! -path "*/run/*" -delete
find . -iname "*.mpe" ! -path "*/run/*" -delete
find . -iname "*.mpv" ! -path "*/run/*" -delete
find . -iname "*.ogg" ! -path "*/run/*" -delete
find . -iname "*.m4p" ! -path "*/run/*" -delete
find . -iname "*.m4v" ! -path "*/run/*" -delete
find . -iname "*.avi" ! -path "*/run/*" -delete
find . -iname "*.wmv" ! -path "*/run/*" -delete
find . -iname "*.mov" ! -path "*/run/*" -delete
find . -iname "*.qt" ! -path "*/run/*" -delete
find . -iname "*.flv" ! -path "*/run/*" -delete
find . -iname "*.swf" !  -path "*/run/*" -delete
find . -iname "*.avchd" ! -path "*/run/*" -delete
find . -iname "*.m4a" ! -path "*/run/*" -delete
find . -iname "*.flac" ! -path "*/run/*" -delete
find . -iname "*.wav" ! -path "*/run/*" -delete
find . -iname "*.wma" ! -path "*/run/*" -delete
find . -iname "*.aac" ! -path "*/run/*" -delete

# File Permissions 

chmod 740 /root/.bash_history
echo Bash history set

chmod 600 /etc/shadow
echo Shadow file permissions configured

chmod 600 /etc/passwd
echo Passwd file permissions configured


chmod 1777 /tmp 
echo “Sticky bit set on tmp”
sleep 30

sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
sed -i '161s/.*/PASS_MIN_DAYS\o01110/' /etc/login.defs
sed -i '162s/.*/PASS_MIN_LEN\o01112/' /etc/login.defs
sed -i '163s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs
sed -i ‘279s/.*/ENCRYPT_METHOD\o011SHA512/’ /etc/login.defs

apt-get install libpam-cracklib
echo > /etc/pam.d/common-password
echo -e "#As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the "Primary" block)\npassword        requisite                       pam_cracklib.so retry=3 remember=5 minlen=12 difok=3 ucredit=1 lcredit=1 dcredit=1 ocredit=1\npassword        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512\n# here's the fallback if no module succeeds\npassword        requisite                       pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword        required                        pam_permit.so\n# and here are more per-package modules (the "Additional" block)\npassword        optional        pam_gnome_keyring.so\n# end of pam-auth-update config" >> /etc/pam.d/common-password


sleep 30
echo > /etc/sysctl.conf
echo -e "# Controls the System Request debugging functionality of the kernel\nkernel.sysrq = 0\n\n#Controls whether core dumps will append the PID to the core filename.\n# Useful fordebugging multi-threaded applications.\nkernel.core_uses_pid = 1\n\n#Allow for more PIDs\nkernel.pid_max = 65535\n\n# The contents of /proc/<pid>/maps and smaps files are only visible to\n# readers that are allowed to ptrace() the process\nkernel.maps_protect=1\n\n#Enable ExecShield protection\nkernel.exec-shield =1\nkernel.randomize_va_space=2\n\n# Controls the maximum size of a message, in bytes\nkernel.msgmnb = 65535\n\n# Controls the default maxmimum size of a mesage queue\nkernel.msgmax = 65535\n\n# Restrict core dumps\nfs.suid_dumpable = 0\n\n# Hide exposed kernel pointers\nkernel.kptr_restrict = 1\n\n\n\n###\n### IMPROVE SYSTEM MEMORY MANAGEMENT ###\n###\n\n# Increase size of file handles and inode cache\nfs.file-max = 209708\n\n# Do less swapping\nvm.swappiness = 30\nvm.dirty_ratio = 30\nvm.dirty_background_ratio = 5\n\n# specifies the minimum virtual address that a process is allowed to mmap\nvm.mmap_min_addr = 4096\n\n# 50% overcommitment of available memory\nvm.overcommit_ratio = 50\nvm.overcommit_memory = 0\n\n# Set maximum amount of memory allocated to shm to 256MB\nkernel.shmmax = 268435456\nkernel.shmall = 268435456\n\n# Keep at least 64MB of free RAM space available\nvm.min_free_kbytes = 65535\n\n\n\n###\n### GENERAL NETWORK SECURITY OPTIONS ###\n###\n\n#Prevent SYN attack, enable SYNcookies (they will kick-in when the max_syn_backlog reached)\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_syn_retries = 2\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_max_syn_backlog = 4096\n\n# Disables packet forwarding\nnet.ipv4.ip_forward = 0\nnet.ipv4.conf.all.forwarding = 0\nnet.ipv4.conf.default.forwarding = 0\nnet.ipv6.conf.all.forwarding = 0\nnet.ipv6.conf.default.forwarding = 0\n\n# Disables IP source routing\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Enable IP spoofing protection, turn on source route verification\nnet.ipv4.conf.all.rp_filter= 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Disable ICMP Redirect Acceptance\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv4.conf.all.secure_redirects = 0\nnet.ipv4.conf.default.secure_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Enable Log Spoofed Packets, Source Routed Packets, Redirect Packets\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.conf.default.log_martians = 1\n\n# Decrease the time default value for tcp_fin_timeout connection\nnet.ipv4.tcp_fin_timeout = 7\n\n# Decrease the time default value for connections to keep alive\nnet.ipv4.tcp_keepalive_time = 300\nnet.ipv4.tcp_keepalive_probes = 5\nnet.ipv4.tcp_keepalive_intvl = 15\n\n# Don't relay bootp\nnet.ipv4.conf.all.bootp_relay = 0\n\n# Don't proxy arp for anyone\nnet.ipv4.conf.all.proxy_arp = 0\n\n# Turn on the tcp_timestamps, accurate timestamp make TCP congestion control algorithms work better\nnet.ipv4.tcp_timestamps = 1\n\n# Don't ignore directed pings\nnet.ipv4.icmp_echo_ignore_all = 0\n\n# Enable ignoring broadcasts request\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Enable bad error message Protection\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Allowed local port range\nnet.ipv4.ip_local_port_range = 16384 65535\n\n# Enable a fix for RFC1337 - time-wait assassination hazards in TCP\nnet.ipv4.tcp_rfc1337 = 1\n\n# Do not auto-configure IPv6\nnet.ipv6.conf.all.autoconf=0\nnet.ipv6.conf.all.accept_ra=0\nnet.ipv6.conf.default.autoconf=0\nnet.ipv6.conf.default.accept_ra=0\nnet.ipv6.conf.eth0.autoconf=0\nnet.ipv6.conf.eth0.accept_ra=0\n\n\n\n###\n### TUNING NETWORK PERFORMANCE ###\n###\n\n# Use BBR TCP congestion control and set tcp_notsent_lowat to 16384 to ensure HTTP/2 prioritization works optimally\n# Do a 'modprobe tcp_bbr' first (kernel > 4.9)\n# Fall-back to htcp if bbr is unavailable (older kernels)\nnet.ipv4.tcp_congestion_control = htcp\nnet.ipv4.tcp_congestion_control = bbr\nnet.ipv4.tcp_notsent_lowat = 16384\n\n# For servers with tcp-heavy workloads, enable 'fq' queue management scheduler (kernel > 3.12)\nnet.core.default_qdisc = fq\n\n# Turn on the tcp_window_scaling\nnet.ipv4.tcp_window_scaling = 1\n\n# Increase the read-buffer space allocatable\nnet.ipv4.tcp_rmem = 8192 87380 16777216\nnet.ipv4.udp_rmem_min = 16384\nnet.core.rmem_default = 262144\nnet.core.rmem_max = 16777216\n\n# Increase the write-buffer-space allocatable\nnet.ipv4.tcp_wmem = 8192 65536 16777216\nnet.ipv4.udp_wmem_min = 16384\nnet.core.wmem_default = 262144\nnet.core.wmem_max = 16777216\n\n# Increase number of incoming connections\nnet.core.somaxconn = 32768\n\n# Increase number of incoming connections backlog\nnet.core.netdev_max_backlog = 16384\nnet.core.dev_weight = 64\n\n# Increase the maximum amount of option memory buffers\nnet.core.optmem_max = 65535\n\n# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks\nnet.ipv4.tcp_max_tw_buckets = 1440000\n\n# try to reuse time-wait connections, but don't recycle them (recycle can break clients behind NAT)\nnet.ipv4.tcp_tw_recycle = 0\n
net.ipv4.tcp_tw_reuse = 1\n\n# Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory\nnet.ipv4.tcp_max_orphans = 16384\nnet.ipv4.tcp_orphan_retries = 0\n\n# Limit the maximum memory used to reassemble IP fragments (CVE-2018-5391)\nnet.ipv4.ipfrag_low_thresh = 196608\nnet.ipv6.ip6frag_low_thresh = 196608\nnet.ipv4.ipfrag_high_thresh = 262144\nnet.ipv6.ip6frag_high_thresh = 262144\n\n# don't cache ssthresh from previous connection\nnet.ipv4.tcp_no_metrics_save = 1\nnet.ipv4.tcp_moderate_rcvbuf = 1\n\n# Increase size of RPC datagram queue length\nnet.unix.max_dgram_qlen = 50\n\n# Don't allow the arp table to become bigger than this\nnet.ipv4.neigh.default.gc_thresh3 = 2048\n\n# Tell the gc when to become aggressive with arp table cleaning.\n# Adjust this based on size of the LAN. 1024 is suitable for most /24 networks\nnet.ipv4.neigh.default.gc_thresh2 = 1024\n\n# Adjust where the gc will leave arp table alone - set to 32.\nnet.ipv4.neigh.default.gc_thresh1 = 32\n\n# Adjust to arp table gc to clean-up more often\nnet.ipv4.neigh.default.gc_interval = 30\n\n# Increase TCP queue length\nnet.ipv4.neigh.default.proxy_qlen = 96\nnet.ipv4.neigh.default.unres_qlen = 6\n\n# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesn't work for you\nnet.ipv4.tcp_ecn = 1\nnet.ipv4.tcp_reordering = 3\n\n# How many times to retry killing an alive TCP connection\nnet.ipv4.tcp_retries2 = 15\nnet.ipv4.tcp_retries1 = 3\n\n# Avoid falling back to slow start after a connection goes idle\n#keeps our cwnd large with the keep alive connections (kernel > 3.6)\nnet.ipv4.tcp_slow_start_after_idle = 0\n\n# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7)\nnet.ipv4.tcp_fastopen = 3\n# This will enusre that immediatly subsequent connections use the new values\nnet.ipv4.route.flush = 1\nnet.ipv6.route.flush = 1
" >> /etc/sysctl.conf
sysctl --system
echo Sysctl has been configured.

sleep 30
printf 'y'| sudo apt remove maltego
printf 'y' |sudo apt remove msfpc
printf 'y' |sudo apt remove set
printf 'y' |sudo apt remove faraday 
printf 'y' |sudo apt remove recordmydesktop
printf 'y' |sudo apt remove pipal
printf 'y' |sudo apt remove cutycapt
printf 'y' |sudo apt remove hashdeep
printf 'y' |sudo apt remove bulk-extractor
printf 'y' |sudo apt remove binwalk
printf 'y' |sudo apt remove autopsy
printf 'y' |sudo apt remove sleuthkit
printf 'y' |sudo apt remove pdfid
printf 'y' |sudo apt remove pdf-parser
printf 'y' |sudo apt remove forensic-artifacts
printf 'y' |sudo apt remove guymager
printf 'y' |sudo apt remove magicrescue
printf 'y' |sudo apt remove scalpel
printf 'y' |sudo apt remove scrounge-ntfs
printf 'y' |sudo apt remove dbd
printf 'y' |sudo apt remove powersploit
printf 'y' |sudo apt remove sbd
printf 'y' |sudo apt remove dns2tcp
printf 'y' |sudo apt remove exe2hexbat
printf 'y' |sudo apt remove iodine
printf 'y' |sudo apt remove miredo
printf 'y' |sudo apt remove proxychains4
printf 'y' |sudo apt remove proxytunnel
printf 'y' |sudo apt remove ptunnel
printf 'y' |sudo apt remove pwnat
printf 'y' |sudo apt remove sslh
printf 'y' |sudo apt remove stunnel4
printf 'y' |sudo apt remove udptunnel
printf 'y' |sudo apt remove laudanum
printf 'y' |sudo apt remove weevely
printf 'y' |sudo apt remove mimikatz
printf 'y' |sudo apt remove dnschef
printf 'y' |sudo apt remove netsniff-ng
printf 'y' |sudo apt remove rebind
printf 'y' |sudo apt remove sslsplit
printf 'y' |sudo apt remove tcpreplay
printf 'y' |sudo apt remove ettercap-graphical
printf 'y' |sudo apt remove macchanger
printf 'y' |sudo apt remove mitmproxy
printf 'y' |sudo apt remove responder
printf 'y' |sudo apt remove wireshark
printf 'y' |sudo apt remove metasploit-framework
printf 'y' |sudo apt remove exploitdb
printf 'y' |sudo apt remove sqlmap
printf 'y' |sudo apt remove sqlitebrowser
printf 'y' |sudo apt remove bully
printf 'y' |sudo apt remove fern-wifi-cracker
printf 'y' |sudo apt remove spooftooph
printf 'y' |sudo apt remove aircrack-ng
printf 'y' |sudo apt remove kismet
printf 'y' |sudo apt remove pixiewps
printf 'y' |sudo apt remove reaver
printf 'y' |sudo apt remove wifite
printf 'y' |sudo apt remove clang
printf 'y' |sudo apt remove nasm
printf 'y' |sudo apt remove radare2
printf 'y' |sudo apt remove chntpw
printf 'y' |sudo apt remove hashcat
printf 'y' |sudo apt remove hashid
printf 'y' |sudo apt remove hash-identifier
printf 'y' |sudo apt remove ophcrack
printf 'y' |sudo apt remove ophcrack-cli
printf 'y' |sudo apt remove samdump2
printf 'y' |sudo apt remove hydra
printf 'y' |sudo apt remove hydra-gtk
printf 'y' |sudo apt remove onesixtyone
printf 'y' |sudo apt remove patator
printf 'y' |sudo apt remove thc-pptp-bruter
printf 'y' |sudo apt remove passing-the-hash
printf 'y' |sudo apt remove mimikatz
printf 'y' |sudo apt remove smbmap
printf 'y' |sudo apt remove cewl
printf 'y' |sudo apt remove crunch
printf 'y' |sudo apt remove john
printf 'y' |sudo apt remove medusa
printf 'y' |sudo apt remove ncrack
printf 'y' |sudo apt remove wordlists
printf 'y' |sudo apt remove rsmangler
printf 'y' |sudo apt remove dnsenum
printf 'y' |sudo apt remove dnsrecon
printf 'y' |sudo apt remove fierce
printf 'y' |sudo apt remove lbd
printf 'y' |sudo apt remove wafw00f
printf 'y' |sudo apt remove arping
printf 'y' |sudo apt remove fping
printf 'y' |sudo apt remove hping3
printf 'y' |sudo apt remove masscan
printf 'y' |sudo apt remove thc-ipv6
printf 'y' |sudo apt remove nmap
printf 'y' |sudo apt remove theharvester
printf 'y' |sudo apt remove netdiscover
printf 'y' |sudo apt remove netmask
printf 'y' |sudo apt remove enum4linux
printf 'y' |sudo apt remove nbtscan
printf 'y' |sudo apt remove smbmap
printf 'y' |sudo apt remove swaks
printf 'y' |sudo apt remove onesixtyone
printf 'y' |sudo apt remove snmpcheck
printf 'y' |sudo apt remove ssldump
printf 'y' |sudo apt remove sslh
printf 'y' |sudo apt remove sslscan
printf 'y' |sudo apt remove sslyze
printf 'y' |sudo apt remove dmitry
printf 'y' |sudo apt remove ike-scan
printf 'y' |sudo apt remove legion
printf 'y' |sudo apt remove recon-ng
printf 'y' |sudo apt remove spike
printf 'y' |sudo apt remove voiphopper
printf 'y' |sudo apt remove legion
printf 'y' |sudo apt remove nikto
printf 'y' |sudo apt remove nmap
printf 'y' |sudo apt remove unix-privesc-check
printf 'y' |sudo apt remove wpscan
printf 'y' |sudo apt remove burpsuite
printf 'y' |sudo apt remove dirb
printf 'y' |sudo apt remove dirbuster
printf 'y' |sudo apt remove wfuzz
printf 'y' |sudo apt remove cadaver
printf 'y' |sudo apt remove davtest
printf 'y' |sudo apt remove skipfish
printf 'y' |sudo apt remove wapiti
printf 'y' |sudo apt remove whatweb
printf 'y' |sudo apt remove commix
printf 'y' |sudo apt remove zaproxy
printf 'y' |sudo apt remove freerdp2-x11
printf 'y' |sudo apt remove scalpel
printf 'y' |sudo apt remove spiderfoot
printf ‘y’ |sudo apt remove yersinia
printf 'y' |sudo apt autoclean 
printf 'y' |sudo apt autoremove
printf 'y' |sudo apt update

journalctl | grep “Execute Disable”
#apt-get install -y clamav 
#freshclam update
#clamscan -r / | grep FOUND >> ClamResults.txt

find /home -iname “*.txt” -print > EverybodyTextFiles.txt
find /home -iname “*.pdf” -print > EverybodyPDFFiles.txt
find /home -iname “*.docx” -print > EverybodyDocFiles.txt
find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \; >> WriteableFiles.txt


dpkg -l > packagelist.txt
echo /etc/systemd/system >> SystemServices.txt




echo “check your document folder for more info”
mkdir /home/backups

        PASS="LBC2DONS!"
        #remove keylogger before doing password stuff
        apt purge -y logkeys*
        #Get all users and uids from passwd and put them into seperate files
        cut -d: -f1 /etc/passwd > /home/backups/usrs.txt
        cut -d: -f3 /etc/passwd > /home/backups/uids.txt

        #convert ^ files into arrays
        all_usrs=()
        all_uids=()
        users=()
        for i in $(cat /home/backups/usrs.txt); do
          all_usrs+=($i)
        done

        for i in $(cat /home/backups/uids.txt); do
          all_uids+=($i)
        done

        #loop through uids for ones that are 0 or >1000
        for i in ${!all_uids[@]}; do
          if [ ${all_uids[$i]} -eq 0 ] || [ ${all_uids[$i]} -ge 1000 ];
          then
            users+=(${all_usrs[$i]})
          fi
        done

        #ask if the user needs to be a user or admin
        admins=()
        for i in ${!users[@]}; do
          printf "Do u wish to curb stomp ${users[$i]}: "
          read answer
          if [ $answer == 'y' ];
          then
            userdel ${users[i]}
            echo "Casey used ginger"
            echo "${users[$i]} died"
          else
            echo -e "$PASS\n$PASS" | passwd ${users[$i]}
            printf "What is this users power level: "
            read answer

            if [ $answer == 'a' ];
            then
              admins+="${users[$i]},"
              echo "${users[$i]} is now a fucking god"
            else
              echo "${users[$i]} is now a useless user"
            fi
          fi
        done

        sed -i "/sudo:x:27:/c\sudo:x:27:${admins[0]}" /etc/group

#apt-get install lightdm

sleep 15
echo "check permissions on config files of crit services"
sleep 5
echo "look at notes and githubs to properly config files"
sleep 5
echo "config firefox with HTTPS only and block malicious downloads"
sleep 5
echo "look in EverybodyTextFiles, EverybodyPDFFiles, EveryBodyDocFiles, SystemServices, WriteableFiles, and packagelist for any missed items"
sleep 5
echo "take pictures and notes of every score"

#apt-get upgrade

#echo allow-guest=false >> /etc/lightdm/users.conf
#echo greeter-show-remote-login=false >> /etc/lightdm/users.conf
