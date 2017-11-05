#!/bin/sh
#############################################################################################################################
#CIS CentOS Linux 7 Benchmark v2.1.1
#Si vas a usar este script ten en cuenta lo siguiente:                                                                      #
########################################################README###############################################################
#Editar la linea que configura el archivo /etc/hosts.allow y agregar las redes permitidas. (3.4.2)                          #
#Verificar que en la configuracion del archivo /etc/ssh/sshd_config esten permitidos los usuarios administradores. (5.2.15) #
#Configurar el servidor NTP correcto. (2.2.1.2) y (2.2.1.3)                                                                 #
#Configurar el servidor de logs correcto. (4.2.1.4)                                                                         #
#############################################################################################################################
#1 Initial Setup
########################################################################################
##############################
#1.1 Filesystem configuration#
##############################
#1.1.1 Disable unused filesystems
#1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored) L1 L1
#1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored) L1 L1
#1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored) L1 L1
#1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored) L1 L1
#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored) L1 L1
#1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored) L1 L1
#1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored) L1 L1
#1.1.1.8 Ensure mounting of FAT filesystems is disabled (Scored) L1 L2
echo "install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true" > /etc/modprobe.d/CIS.conf
#1.1.2 Ensure separate partition exists for /tmp (Scored) L2 L2
#1.1.3 Ensure nodev option set on /tmp partition (Scored) L1 L1
#1.1.4 Ensure nosuid option set on /tmp partition (Scored) L1 L1
#1.1.5 Ensure noexec option set on /tmp partition (Scored) L1 L1
sed -i '/ \/tmp/s/defaults/defaults,nodev,nosuid,noexec/g' /etc/fstab
#1.1.6 Ensure separate partition exists for /var (Scored) L2 L2
#1.1.7 Ensure separate partition exists for /var/tmp (Scored) L2 L2
#1.1.8 Ensure nodev option set on /var/tmp partition (Scored) L1 L1
#1.1.9 Ensure nosuid option set on /var/tmp partition (Scored) L1 L1
#1.1.10 Ensure noexec option set on /var/tmp partition (Scored) L1 L1
sed -i '/\/var\/tmp/s/defaults/defaults,nodev,nosuid,noexec/g' /etc/fstab
#1.1.11 Ensure separate partition exists for /var/log (Scored) L2 L2
#1.1.12 Ensure separate partition exists for /var/log/audit (Scored) L2 L2
#1.1.13 Ensure separate partition exists for /home (Scored) L2 L2
#1.1.14 Ensure nodev option set on /home partition (Scored) L1 L1
sed -i '/\/home/s/defaults/defaults,nodev/g' /etc/fstab
#1.1.15 Ensure nodev option set on /dev/shm partition (Scored) L1 L1
#1.1.16 Ensure nosuid option set on /dev/shm partition (Scored) L1 L1
#1.1.17 Ensure noexec option set on /dev/shm partition (Scored) L1 L1
sed -i '/\/dev\/shm/s/defaults/defaults,nodev,nosuid,noexec/g' /etc/fstab
#1.1.18 Ensure nodev option set on removable media partitions (Not Scored) L1 L1
#1.1.19 Ensure nosuid option set on removable media partitions (Not Scored) L1 L1
#1.1.20 Ensure noexec option set on removable media partitions (Not Scored) L1 L1
#1.1.21 Ensure sticky bit is set on all world-writable directories (Scored) L1 L1
df --local -P | awk {'print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
#1.1.22 Disable Automounting (Scored) L1 L2
systemctl disable autofs
########################################################################################
################################
#1.2 Configure Software Updates#
################################
#1.2.1 Ensure package manager repositories are configured (Not Scored) L1 L1
#1.2.2 Ensure GPG keys are configured (Not Scored) L1 L1
#1.2.3 Ensure gpgcheck is globally activated (Scored) L1 L1
gpg --quiet --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf
########################################################################################
###################################
#1.3 Filesystem Integrity Checking#
###################################
#1.3.1 Ensure AIDE is installed (Scored) L1 L1
yum install aide -y
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'
#1.3.2 Ensure filesystem integrity is regularly checked (Scored) L1 L1
echo '0 5 * * * /usr/sbin/aide --check' > /var/spool/cron/root
########################################################################################
##########################
#1.4 Secure Boot Settings#
##########################
#1.4.1 Ensure permissions on bootloader config are configured (Scored) L1 L1
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
#1.4.2 Ensure bootloader password is set (Scored) L1 L1
echo "cat <<EOF
set superusers=\"stormtroopers\"
password_pbkdf2 bobafett grub.pbkdf2.sha512.10000.6D6CA06087C0C24D31D66CBBE024976CF3EACBA55F42642D3A6071DE0406FBD28C0391C52FF90D0B9C293A9418867E1BACB1A8188766387AA4D30983BE15B1E15014AD83993121787BE97484BE7E4AB4E820F8146A1FFB145B1C152D07910C041770F5.43BCB244952805E1301E889A4CBFCCC5AE997541911967426A12A617EE
EOF" >> /etc/grub.d/01_users
grub2-mkconfig -o /boot/grub2/grub.cfg
#1.4.3 Ensure authentication required for single user mode (Not Scored) L1 L1
########################################################################################
##################################
#1.5 Additional Process Hardening#
##################################
#1.5.1 Ensure core dumps are restricted (Scored) L1 L1
sed -i '/End/ i * hard core 0' /etc/security/limits.conf
sed -i '$ a fs.suid_dumpable = 0' /etc/sysctl.conf
#1.5.2 Ensure XD/NX support is enabled (Not Scored) L1 L1
#1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored) L1 L1
sed -i '$ a kernel.randomize_va_space = 2' /etc/sysctl.conf
#1.5.4 Ensure prelink is disabled (Scored) L1 L1
prelink -ua
yum remove prelink -y
########################################################################################
##############################
#1.6 Mandatory Access Control#
##############################
#1.6.1.1 Ensure SELinux is not disabled in bootloader configuration (Scored) L2 L2
sed -i 's/selinux=0/selinux=1/g' /boot/grub2/grub.cfg
sed -i 's/enforcing=0/enforcing=1/g' /boot/grub2/grub.cfg
#1.6.1.2 Ensure the SELinux state is enforcing (Scored) L2 L2
sed -i '/^SELINUX=/ c SELINUX=enforcing' /etc/selinux/config
#1.6.1.3 Ensure SELinux policy is configured (Scored) L2 L2
sed -i '/^SELINUXTYPE=/ c SELINUXTYPE=targeted' /etc/selinux/config
#1.6.1.4 Ensure SETroubleshoot is not installed (Scored) L2
yum remove setroubleshoot -y
#1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed (Scored) L2 L2
yum erase mcstrans
#1.6.1.6 Ensure no unconfined daemons exist (Scored) L2 L2
#1.6.2 Ensure SELinux is installed (Scored) L2 L2
yum install libselinux -y
########################################################################################
#####################
#1.7 Warning Banners#
#####################
#1.7.1.1 Ensure message of the day is configured properly (Scored) L1 L1
echo "******************************************
* This is an COMPANY system, restricted *
* to authorized individuals. This system *
* is subject to monitoring. By logging   *
* into this system you agree to have all *
* your communications monitored.         *
* Unauthorized users, access, and/or     *
* modification will be prosecuted.       *
******************************************" > /etc/motd
egrep '(\\v|\\r|\\m|\\s)' /etc/motd
#1.7.1.2 Ensure local login warning banner is configured properly (Not Scored) L1 L1
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
#1.7.1.3 Ensure remote login warning banner is configured properly (Not Scored) L1 L1
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
#1.7.1.4 Ensure permissions on /etc/motd are configured (Not Scored) L1 L1
chown root:root /etc/motd
chmod 644 /etc/motd
#1.7.1.5 Ensure permissions on /etc/issue are configured (Scored) L1 L1
chown root:root /etc/issue
chmod 644 /etc/issue
#1.7.1.6 Ensure permissions on /etc/issue.net are configured (Not Scored) L1 L1
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
#1.7.2 Ensure GDM login banner is configured (Scored) L1 L1
########################################################################################
#1.8 Ensure updates, patches, and additional security software are installed (Not Scored) L1 L1
########################################################################################
yum update -y
############
#2 Services#
############
########################################################################################
####################
#2.1 inetd Services#
####################
#2.1.1 Ensure chargen services are not enabled (Scored) L1 L1
chkconfig chargen-dgram off
chkconfig chargen-stream off
#2.1.2 Ensure daytime services are not enabled (Scored) L1 L1
chkconfig daytime-dgram off
chkconfig daytime-stream off
#2.1.3 Ensure discard services are not enabled (Scored) L1 L1
chkconfig discard-dgram off
chkconfig discard-stream off
#2.1.4 Ensure echo services are not enabled (Scored) L1 L1
chkconfig echo-dgram off
chkconfig echo-stream off
#2.1.5 Ensure time services are not enabled (Scored) L1 L1
chkconfig time-dgram off
chkconfig time-stream off
#2.1.6 Ensure tftp server is not enabled (Scored) L1 L1
chkconfig tftp off
#2.1.7 Ensure xinetd is not enabled (Scored) L1 L1
systemctl disable xinetd
########################################################################################
##############################
#2.2 Special Purpose Services#
##############################
#2.2.1.1 Ensure time synchronization is in use (Not Scored) L1 L1
yum install ntp -y
yum install chrony -y
#2.2.1.2 Ensure ntp is configured (Scored) L1 L1
echo "driftfile /var/lib/ntp/drift
restrict -4 default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
server ntp.domain.com
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor" > /etc/ntp.conf
echo 'OPTIONS="-u ntp:ntp"' > /etc/sysconfig/ntpd
#2.2.1.3 Ensure chrony is configured (Scored) L1 L1
echo "server ntp.domain.com iburst
stratumweight 0
driftfile /var/lib/chrony/drift
rtcsync
makestep 10 3
bindcmdaddress 127.0.0.1
bindcmdaddress ::1
keyfile /etc/chrony.keys
commandkey 1
generatecommandkey
noclientlog
logchange 0.5" > /etc/chrony.conf
echo 'OPTIONS="-u chrony"' > /etc/sysconfig/chronyd
#2.2.2 Ensure X Window System is not installed (Scored) L1
yum remove xorg-x11* -y
#2.2.3 Ensure Avahi Server is not enabled (Scored) L1 L1
systemctl disable avahi-daemon
#2.2.4 Ensure CUPS is not enabled (Scored) L1 L2
systemctl disable cups
#2.2.5 Ensure DHCP Server is not enabled (Scored) L1 L1
systemctl disable dhcpd
#2.2.6 Ensure LDAP server is not enabled (Scored) L1 L1
systemctl disable slapd
#2.2.7 Ensure NFS and RPC are not enabled (Scored) L1 L1
systemctl disable nfs
systemctl disable rpcbind
#2.2.8 Ensure DNS Server is not enabled (Scored) L1 L1
systemctl disable named
#2.2.9 Ensure FTP Server is not enabled (Scored) L1 L1
systemctl disable vsftpd
#2.2.10 Ensure HTTP server is not enabled (Scored) L1 L1
systemctl disable httpd
#2.2.11 Ensure IMAP and POP3 server is not enabled (Scored) L1 L1
systemctl disable dovecot
#2.2.12 Ensure Samba is not enabled (Scored) L1 L1
systemctl disable smb
#2.2.13 Ensure HTTP Proxy Server is not enabled (Scored) L1 L1
 systemctl disable squid
#2.2.14 Ensure SNMP Server is not enabled (Scored) L1 L1
systemctl disable snmpd
#2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored) L1 L1
systemctl disable postfix
#2.2.16 Ensure NIS Server is not enabled (Scored) L1 L1
systemctl disable ypserv
#2.2.17 Ensure rsh server is not enabled (Scored) L1 L1
systemctl disable rsh.socket
systemctl disable rlogin.socket
systemctl disable rexec.socket
#2.2.18 Ensure telnet server is not enabled (Scored) L1 L1
systemctl disable telnet.socket
#2.2.19 Ensure tftp server is not enabled (Scored) L1 L1
systemctl disable tftp.socket
#2.2.20 Ensure rsync service is not enabled (Scored) L1 L1
systemctl disable rsyncd
#2.2.21 Ensure talk server is not enabled (Scored) L1 L1
systemctl disable ntalk
########################################################################################
#####################
#2.3 Service Clients#
#####################
#2.3.1 Ensure NIS Client is not installed (Scored) L1 L1
yum remove ypbind -y
#2.3.2 Ensure rsh client is not installed (Scored) L1 L1
yum remove rsh -y
#2.3.3 Ensure talk client is not installed (Scored) L1 L1
yum remove talk -y
#2.3.4 Ensure telnet client is not installed (Scored) L1 L1
yum remove telnet -y
#2.3.5 Ensure LDAP client is not installed (Scored) L1 L1
yum remove openldap-clients -y
########################################################################################
#########################
#3 Network Configuration#
#########################
####################################
#3.1 Network Parameters (Host Only)#
####################################
#3.1.1 Ensure IP forwarding is disabled (Scored) L1 L1
sed -i '$ a net.ipv4.ip_forward = 0' /etc/sysctl.conf
#3.1.2 Ensure packet redirect sending is disabled (Scored) L1 L1
sed -i '$ a net.ipv4.conf.all.send_redirects = 0' /etc/sysctl.conf
sed -i '$ a net.ipv4.conf.default.send_redirects = 0' /etc/sysctl.conf
##########################################
#3.2 Network Parameters (Host and Router)#
##########################################
#3.2.1 Ensure source routed packets are not accepted (Scored) L1 L1
sed -i '$ a net.ipv4.conf.all.accept_source_route = 0' /etc/sysctl.conf
sed -i '$ a net.ipv4.conf.default.accept_source_route = 0' /etc/sysctl.conf
#3.2.2 Ensure ICMP redirects are not accepted (Scored) L1 L1
sed -i '$ a net.ipv4.conf.all.accept_redirects = 0' /etc/sysctl.conf
sed -i '$ a net.ipv4.conf.default.accept_redirects = 0' /etc/sysctl.conf
#3.2.3 Ensure secure ICMP redirects are not accepted (Scored) L1 L1
sed -i '$ a net.ipv4.conf.all.secure_redirects = 0' /etc/sysctl.conf
sed -i '$ a net.ipv4.conf.default.secure_redirects = 0' /etc/sysctl.conf
#3.2.4 Ensure suspicious packets are logged (Scored) L1 L1
sed -i '$ a net.ipv4.conf.all.log_martians=1' /etc/sysctl.conf
sed -i '$ a net.ipv4.conf.default.log_martians=1' /etc/sysctl.conf
#3.2.5 Ensure broadcast ICMP requests are ignored (Scored) L1 L1
sed -i '$ a net.ipv4.icmp_echo_ignore_broadcasts = 1' /etc/sysctl.conf
#3.2.6 Ensure bogus ICMP responses are ignored (Scored) L1 L1
sed -i '$ a net.ipv4.icmp_ignore_bogus_error_responses = 1' /etc/sysctl.conf
#3.2.7 Ensure Reverse Path Filtering is enabled (Scored) L1 L1
sed -i '$ a net.ipv4.conf.all.rp_filter = 1' /etc/sysctl.conf
sed -i '$ a net.ipv4.conf.default.rp_filter = 1' /etc/sysctl.conf
#3.2.8 Ensure TCP SYN Cookies is enabled (Scored) L1 L1
sed -i '$ a net.ipv4.tcp_syncookies = 1' /etc/sysctl.conf
#3.3 IPv6
#3.3.1 Ensure IPv6 router advertisements are not accepted (Scored) L1 L1
sed -i '$ a net.ipv6.conf.all.accept_ra = 0' /etc/sysctl.conf
sed -i '$ a net.ipv6.conf.default.accept_ra=0' /etc/sysctl.conf
#3.3.2 Ensure IPv6 redirects are not accepted (Scored) L1 L1
sed -i '$ a net.ipv6.conf.all.accept_redirects = 0' /etc/sysctl.conf
sed -i '$ a net.ipv6.conf.default.accept_redirects = 0' /etc/sysctl.conf
#3.3.3 Ensure IPv6 is disabled (Not Scored) L1 L1
sed -i '$ a net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf
sed -i '$ a options ipv6 disable=1' /etc/modprobe.d/CIS.conf
#3.4 TCP Wrappers
#3.4.1 Ensure TCP Wrappers is installed (Scored) L1 L1
yum install tcp_wrappers -y
#3.4.2 Ensure /etc/hosts.allow is configured (Scored) L1 L1
echo "ALL: 192.168.0.x/32 192.1568.1.x/32" >/etc/hosts.allow
#3.4.3 Ensure /etc/hosts.deny is configured (Scored) L1 L1
echo "ALL: ALL" >> /etc/hosts.deny
#3.4.4 Ensure permissions on /etc/hosts.allow are configured (Scored) L1 L1
/bin/chmod 644 /etc/hosts.allow
#3.4.5 Ensure permissions on /etc/hosts.deny are 644 (Scored) L1 L1
/bin/chmod 644 /etc/hosts.deny
#3.5 Uncommon Network Protocols
#3.5.1 Ensure DCCP is disabled (Not Scored) L1 L1
sed -i '$ a install dccp /bin/true' /etc/modprobe.d/CIS.conf
#3.5.2 Ensure SCTP is disabled (Not Scored) L1 L1
sed -i '$ a install sctp /bin/true' /etc/modprobe.d/CIS.conf
#3.5.3 Ensure RDS is disabled (Not Scored) L1 L1
sed -i '$ a install rds /bin/true' /etc/modprobe.d/CIS.conf
#3.5.4 Ensure TIPC is disabled (Not Scored) L1 L1
sed -i '$ a install tipc /bin/true' /etc/modprobe.d/CIS.conf
#3.6 Firewall Configuration
#3.6.1 Ensure iptables is installed (Scored) L1 L1
yum install iptables -y
#3.6.2 Ensure default deny firewall policy (Scored) L1 L1
#iptables -P INPUT DROP
#iptables -P OUTPUT DROP
#iptables -P FORWARD DROP
#3.6.3 Ensure loopback traffic is configured (Scored) L1 L1
#3.6.4 Ensure outbound and established connections are configured (Not Scored) L1 L1
#3.6.5 Ensure firewall rules exist for all open ports (Scored) L1 L1
systemctl enable firewalld
#3.7 Ensure wireless interfaces are disabled (Not Scored) L1 L2
########################################################################################
########################
#4 Logging and Auditing#
########################
##########################################
#4.1 Configure System Accounting (auditd)#
##########################################
#4.1.1.1 Ensure audit log storage size is configured (Not Scored) L2 L2
sed -i /'^max_log_file/ c max_log_file = 1024' /etc/audit/auditd.conf
#4.1.1.2 Ensure system is disabled when audit logs are full (Scored) L2 L2
sed -i /'^space_left_action/ c space_left_action = email' /etc/audit/auditd.conf
sed -i /'^action_mail_acct/ c action_mail_acct = root' /etc/audit/auditd.conf
sed -i /'^admin_space_left_action/ c admin_space_left_action = halt' /etc/audit/auditd.conf
#4.1.1.3 Ensure audit logs are not automatically deleted (Scored) L2 L2
sed -i '$ a max_log_file_action = keep_logs' /etc/audit/auditd.conf
#4.1.2 Ensure auditd service is enabled (Scored) L2 L2
systemctl enable auditd
#4.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored) L2 L2
sed -i s/'^GRUB_CMDLINE_LINUX="'/'GRUB_CMDLINE_LINUX="audit=1 '/ /etc/default/grub
#4.1.4 Ensure events that modify date and time information are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change" > /etc/audit/rules.d/audit.rules
#4.1.5 Ensure events that modify user/group information are collected (Scored) L2 L2
echo "-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#4.1.6 Ensure events that modify the system's network environment are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
#4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (Scored) L2 L2
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
#4.1.8 Ensure login and logout events are collected (Scored) L2 L2
echo "-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/rules.d/audit.rules
#4.1.9 Ensure session initiation information is collected (Scored) L2 L2
echo "-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
#4.1.10 Ensure discretionary access control permission modification events are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
#4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
#4.1.12 Ensure use of privileged commands is collected (Scored) L2 L2
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/audit.rules
#4.1.13 Ensure successful file system mounts are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules
#4.1.14 Ensure file deletion events by users are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
#4.1.15 Ensure changes to system administration scope (sudoers) is collected (Scored) L2 L2
echo "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/rules.d/audit.rules
#4.1.16 Ensure system administrator actions (sudolog) are collected (Scored) L2 L2
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules
#4.1.17 Ensure kernel module loading and unloading is collected (Scored) L2 L2
echo "-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit arch=b32 -S init_module -S delete_module -k modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules
#4.1.18 Ensure the audit configuration is immutable (Scored) L2 L2
echo "-e 2" >> /etc/audit/rules.d/audit.rules
#######################
#4.2 Configure Logging#
#######################
#4.2.1.1 Ensure rsyslog Service is enabled (Scored) L1 L1
yum install rsyslog -y
systemctl enable rsyslog
#4.2.1.2 Ensure logging is configured (Not Scored) L1 L1
echo "auth,user.* /var/log/messages
kern.* /var/log/kern.log
daemon.* /var/log/daemon.log
syslog.* /var/log/syslog
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log" >> /etc/rsyslog.conf
#4.2.1.3 Ensure rsyslog default file permissions configured (Scored) L1 L1
sed -i '$ a $FileCreateMode 0640' /etc/rsyslog.conf
#4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored) L1 L1
sed -i '$ a *.* @@mi.domain.com:514' /etc/rsyslog.conf
#4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored) L1 L1
#4.2.2.1 Ensure syslog-ng service is enabled (Scored) L1 L1
systemctl enable syslog-ng
#4.2.2.2 Ensure logging is configured (Not Scored) L1 L1
#4.2.2.3 Ensure syslog-ng default file permissions configured (Scored) L1 L1
#4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host (Not Scored) L1 L1
#4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored) L1 L1
#4.2.3 Ensure rsyslog or syslog-ng is installed (Scored) L1 L1
yum install rsyslog -y
#4.2.4 Ensure permissions on all logfiles are configured (Scored) L1 L1
find /var/log -type f -exec chmod g-wx,o-rwx {} +
#4.3 Ensure logrotate is configured (Not Scored) L1 L1
########################################################################################
############################################
#5 Access, Authentication and Authorization#
############################################
####################
#5.1 Configure cron#
####################
#5.1.1 Ensure cron daemon is enabled (Scored) L1 L1
systemctl enable crond
#5.1.2 Ensure permissions on /etc/crontab are configured (Scored) L1 L1
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
#5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored) L1 L1
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
#5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored) L1 L1
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
#5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored) L1 L1
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
#5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored) L1 L1
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
#5.1.7 Ensure permissions on /etc/cron.d are configured (Scored) L1 L1
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
#5.1.8 Ensure at/cron is restricted to authorized users (Scored) L1 L1
/bin/rm /etc/cron.deny
/bin/rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
##############################
#5.2 SSH Server Configuration#
##############################
#5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored) L1 L1
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
#5.2.2 Ensure SSH Protocol is set to 2 (Scored) L1 L1
sed -i '/^#Protocol/ c Protocol 2' /etc/ssh/sshd_config
#sed -i '/Protocol/s/^#//g' /etc/ssh/sshd_config
#5.2.3 Ensure SSH LogLevel is set to INFO (Scored) L1 L1
sed -i '/^#LogLevel/ c LogLevel INFO' /etc/ssh/sshd_config
#5.2.4 Ensure SSH X11 forwarding is disabled (Scored) L1 L1
sed -i '/^X11Forwarding/ c X11Forwarding no' /etc/ssh/sshd_config
#5.2.5 Ensure SSH MaxAuthTries is set to 4 or less (Scored) L1 L1
sed -i '/^#MaxAuthTries/ c MaxAuthTries 4' /etc/ssh/sshd_config
#5.2.6 Ensure SSH IgnoreRhosts is enabled (Scored) L1 L1
sed -i '/^#IgnoreRhosts/ c IgnoreRhosts yes' /etc/ssh/sshd_config
#5.2.7 Ensure SSH HostbasedAuthentication is disabled (Scored) L1 L1
sed -i '/^#HostbasedAuthentication/ c HostbasedAuthentication no' /etc/ssh/sshd_config
#5.2.8 Ensure SSH root login is disabled (Scored) L1 L1
sed -i '/^#PermitRootLogin/ c PermitRootLogin no' /etc/ssh/sshd_config
#5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Scored) L1 L1
sed -i '/^#PermitEmptyPasswords/ c PermitEmptyPasswords no' /etc/ssh/sshd_config
#5.2.10 Ensure SSH PermitUserEnvironment is disabled (Scored) L1 L1
sed -i '/^#PermitUserEnvironment/ c PermitUserEnvironment no' /etc/ssh/sshd_config
#5.2.11 Ensure only approved ciphers are used (Scored) L1 L1
sed -i '$ a Ciphers aes128-ctr,aes192-ctr,aes256-ctr' /etc/ssh/sshd_config
#5.2.12 Ensure only approved MAC algorithms are used (Scored) L1 L1
sed -i '$ a MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' /etc/ssh/sshd_config
#5.2.13 Ensure SSH Idle Timeout Interval is configured (Scored) L1 L1
sed -i '/^#ClientAliveInterval/ c ClientAliveInterval 300' /etc/ssh/sshd_config
sed -i '/^#ClientAliveCountMax/ c ClientAliveCountMax 0' /etc/ssh/sshd_config
#5.2.14 Ensure SSH LoginGraceTime is set to one minute or less (Scored) L1 L1
sed -i '/^#LoginGraceTime/ c LoginGraceTime 60' /etc/ssh/sshd_config
#5.2.15 Ensure SSH access is limited (Scored) L1 L1
sed -i '$ a AllowUsers admin_user' /etc/ssh/sshd_config
sed -i '$ a AllowGroups wheel' /etc/ssh/sshd_config
sed -i '$ a DenyUsers ALL' /etc/ssh/sshd_config
sed -i '$ a DenyGroups ALL' /etc/ssh/sshd_config
#5.2.16 Ensure SSH warning banner is configured (Scored) L1 L1
sed -i '/^#Banner/ c Banner \/etc\/issue.net' /etc/ssh/sshd_config
###################
#5.3 Configure PAM#
###################
#5.3.1 Ensure password creation requirements are configured (Scored) L1 L1
sed -i '/^# minlen =/ c minlen=14' /etc/security/pwquality.conf
sed -i '/^# dcredit =/ c dcredit=-1' /etc/security/pwquality.conf
sed -i '/^# ucredit =/ c ucredit=-1' /etc/security/pwquality.conf
sed -i '/^# ocredit =/ c ocredit=-1' /etc/security/pwquality.conf
sed -i '/^# lcredit =/ c lcredit=-1' /etc/security/pwquality.conf
#5.3.2 Ensure lockout for failed password attempts is configured (Scored) L1 L1
content="$(egrep -v "^#|^auth" /etc/pam.d/password-auth)"
echo -e "auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so\n$content" > /etc/pam.d/password-auth
system_auth='/etc/pam.d/system-auth'
content="$(egrep -v "^#|^auth" ${system_auth})"
echo -e "auth required pam_env.so
auth sufficient pam_unix.so remember=5
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so\n$content" > ${system_auth}
#5.3.3 Ensure password reuse is limited (Scored) L1 L1
sed -i '/^password *sufficient/ s/pam_unix.so/pam_unix.so remember=5/' /etc/pam.d/password-auth
#5.3.4 Ensure password hashing algorithm is SHA-512 (Scored) L1 L1
sed -i '/^password *sufficient/ s/pam_unix.so/pam_unix.so remember=5 sha512/' /etc/pam.d/system-auth
###################################
#5.4 User Accounts and Environment#
###################################
#5.4.1.1 Ensure password expiration is 90 days or less (Scored) L1 L1
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
#5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored) L1 L1
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' /etc/login.defs
#5.4.1.3 Ensure password expiration warning days is 7 or more (Scored) L1 L1
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
#5.4.1.4 Ensure inactive password lock is 30 days or less (Scored) L1 L1
useradd -D -f 30
#5.4.2 Ensure system accounts are non-login (Scored) L1 L1
#5.4.3 Ensure default group for the root account is GID 0 (Scored) L1 L1
#5.4.4 Ensure default user umask is 027 or more restrictive (Scored) L1 L1
sed -i 's/umask 0.*$/umask 027/' /etc/bashrc
sed -i 's/umask 0.*$/umask 027/' /etc/profile
#5.5 Ensure root login is restricted to system console (Not Scored) L1 L1
cp /etc/securetty /etc/securetty.orig
echo console > /etc/securetty
#5.6 Ensure access to the su command is restricted (Scored) L1 L1
sed -i '/pam_wheel.so/ s/#//' /etc/pam.d/su
########################################################################################
######################
#6 System Maintenance#
######################
#############################
#6.1 System File Permissions#
#############################
#6.1.1 Audit system file permissions (Not Scored) L2 L2
#6.1.2 Ensure permissions on /etc/passwd are configured (Scored) L1 L1
chown root:root /etc/passwd
chmod 644 /etc/passwd
#6.1.3 Ensure permissions on /etc/shadow are configured (Scored) L1 L1
chown root:root /etc/shadow
chmod 000 /etc/shadow
#6.1.4 Ensure permissions on /etc/group are configured (Scored) L1 L1
chown root:root /etc/group
chmod 644 /etc/group
#6.1.5 Ensure permissions on /etc/gshadow are configured (Scored) L1 L1
chown root:root /etc/gshadow
chmod 000 /etc/gshadow
#6.1.6 Ensure permissions on /etc/passwd- are configured (Scored) L1 L1
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
#6.1.7 Ensure permissions on /etc/shadow- are configured (Scored) L1 L1
chown root:root /etc/shadow-
chmod 600 /etc/shadow-
#6.1.8 Ensure permissions on /etc/group- are configured (Scored) L1 L1
chown root:root /etc/group-
chmod 600 /etc/group-
#6.1.9 Ensure permissions on /etc/gshadow- are configured (Scored) L1 L1
chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-
#6.1.10 Ensure no world writable files exist (Scored) L1 L1
#6.1.11 Ensure no unowned files or directories exist (Scored) L1 L1
#6.1.12 Ensure no ungrouped files or directories exist (Scored) L1 L1
#6.1.13 Audit SUID executables (Not Scored) L1 L1
#6.1.14 Audit SGID executables (Not Scored) L1 L1
#############################
#6.2 User and Group Settings#
#############################
#6.2.1 Ensure password fields are not empty (Scored) L1 L1
#6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored) L1 L1
#6.2.3 Ensure no legacy "+" entries exist in /etc/shadow (Scored) L1 L1
#6.2.4 Ensure no legacy "+" entries exist in /etc/group (Scored) L1 L1
#6.2.5 Ensure root is the only UID 0 account (Scored) L1 L1
#6.2.6 Ensure root PATH Integrity (Scored) L1 L1
#6.2.7 Ensure all users' home directories exist (Scored) L1 L1
#6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored) L1 L1
#6.2.9 Ensure users own their home directories (Scored) L1 L1
#6.2.10 Ensure users' dot files are not group or world writable (Scored) L1 L1
#6.2.11 Ensure no users have .forward files (Scored) L1 L1
#6.2.12 Ensure no users have .netrc files (Scored) L1 L1
#6.2.13 Ensure users' .netrc Files are not group or world accessible (Scored) L1 L1
#6.2.14 Ensure no users have .rhosts files (Scored) L1 L1
#6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored) L1 L1
#6.2.16 Ensure no duplicate UIDs exist (Scored) L1 L1
#6.2.17 Ensure no duplicate GIDs exist (Scored) L1 L1
#6.2.18 Ensure no duplicate user names exist (Scored) L1 L1
#6.2.19 Ensure no duplicate group names exist (Scored) L1 L1
########################################################################################
echo "
HISTFILESIZE=1000000
HISTSIZE=1000000
HISTTIMEFORMAT='%F %T '
PROMPT_COMMAND='history -a'" >> /root/.bashrc
########################################################################################