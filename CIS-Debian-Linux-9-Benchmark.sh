#!/bin/bash
##################################
###CIS Debian Linux 9 Benchmark v1.0.0###
##################################
#############################################################################################################################

#############################################################################################################################
###############################################################
#####################CHANGE THIS###############################
###############################################################
DOMINIO="example.com"
ADMIN_USER="administrator"
HOSTS_ALLOWED="192.168.56.1/32"
COMPANY="COMPANY LTD"
###############################################################
#####################FUNCTIONS#################################
###############################################################
function set_CIS_directive() { file="/etc/modprobe.d/CIS.conf"; if [ ! -e $file ]; then echo -e '\e[1;31m'$file' not found.\e[0m'; echo "#CIS Config" > $file; fi;	if grep "$1" $file; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i "$ a $1" $file; echo -e '\e[1;32mDone\e[0m'; fi }
function set_directive() {      if [ ! -e $3 ]; then echo -e '\e[1;31m'$3' not found.\e[0m'; else if grep "^$1 = $2" $3; then echo -e '\e[1;32mIt was already configured\e[0m'; else if grep "^$1" $3; then sed -i /"^$1/ c $1 = $2" $3; echo -e '\e[1;32mDone\e[0m'; else sed -i "$ a $1 = $2" $3; echo -e '\e[1;32mDone\e[0m'; fi fi fi }
function add_string() {      if [ ! -e $3 ]; then echo -e '\e[1;31m'$3' not found.\e[0m'; else if grep "$1$2" $3; then echo -e '\e[1;32mIt was already configured\e[0m'; else if grep "^$1" $3; then sed -i "/^$1/s/$1/$1$2/g" $3; echo -e '\e[1;32mDone\e[0m'; else sed -i "$ a $1$2" $3; echo -e '\e[1;32mDone\e[0m'; fi fi fi }
function replace_line() {      if [ ! -e $3 ]; then echo -e '\e[1;31m'$3' not found.\e[0m'; else if grep "^$2" $3; then echo -e '\e[1;32mIt was already configured\e[0m'; else if grep "^$1" $3; then sed -i "/^$1/s/$1/$2/g" $3; echo -e '\e[1;32mDone\e[0m'; else sed -i "$ a $2" $3; echo -e '\e[1;32mDone\e[0m'; fi fi fi }
function set_directive_fs() { if [ ! -e $3 ]; then echo -e '\e[1;31m'$3' not found.\e[0m'; echo "$1" > $3; $2; echo -e '\e[1;32mDone\e[0m'; else if grep "^$1" $3; then echo -e '\e[1;32mIt was already configured\e[0m'; fi fi }
###############################################################

#1 Initial Setup
########################################################################################
##############################
#1.1 Filesystem configuration#
##############################
#1.1.1 Disable unused filesystems
#1.1.1.1 Ensure mounting of freevxfs filesystems is disabled (Scored) L1 L1
set_directive_fs "install freevxfs /bin/true" "rmmod freevxfs" /etc/modprobe.d/freevxfs.conf
#1.1.1.2 Ensure mounting of jffs2 filesystems is disabled (Scored) L1 L1
set_directive_fs "install jffs2 /bin/true" "rmmod jffs2" /etc/modprobe.d/jffs2.conf
#1.1.1.3 Ensure mounting of hfs filesystems is disabled (Scored) L1 L1
set_directive_fs "install hfs /bin/true" "rmmod hfs" /etc/modprobe.d/hfs.conf
#1.1.1.4 Ensure mounting of hfsplus filesystems is disabled (Scored) L1 L1
set_directive_fs "install hfsplus /bin/true" "rmmod hfsplus" /etc/modprobe.d/hfsplus.conf
#1.1.1.5 Ensure mounting of udf filesystems is disabled (Scored) L1 L1
set_directive_fs "install udf /bin/true" "rmmod udf" /etc/modprobe.d/udf.conf
#1.1.2.Ensure /tmp is configured (Scored) L1 L1
systemctl unmask tmp.mount
systemctl enable tmp.mount
#1.1.3 Ensure nodev option set on /tmp partition (Scored) L1 L1
if sed -n '/ \/tmp/p' /etc/fstab | grep 'nodev'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/ \/tmp/s/defaults/defaults,nodev/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.4 Ensure nosuid option set on /tmp partition (Scored) L1 L1
if sed -n '/ \/tmp/p' /etc/fstab | grep 'nosuid'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/ \/tmp/s/defaults/defaults,nosuid/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.5 Ensure noexec option set on /tmp partition (Scored) L1 L1
if sed -n '/ \/tmp/p' /etc/fstab | grep 'noexec'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/ \/tmp/s/defaults/defaults,noexec/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.6 Ensure separate partition exists for /var (Scored) L2 L2
#1.1.7 Ensure separate partition exists for /var/tmp (Scored) L2 L2
#1.1.8 Ensure nodev option set on /var/tmp partition (Scored) L1 L1
if sed -n '/\/var\/tmp/p' /etc/fstab | grep 'nodev'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/var\/tmp/s/defaults/defaults,nodev/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.9 Ensure nosuid option set on /var/tmp partition (Scored) L1 L1
if sed -n '/\/var\/tmp/p' /etc/fstab | grep 'nosuid'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/var\/tmp/s/defaults/defaults,nosuid/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.10 Ensure noexec option set on /var/tmp partition (Scored) L1 L1
if sed -n '/\/var\/tmp/p' /etc/fstab | grep 'noexec'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/var\/tmp/s/defaults/defaults,noexec/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.11 Ensure separate partition exists for /var/log (Scored) L2 L2
#1.1.12 Ensure separate partition exists for /var/log/audit (Scored) L2 L2
#1.1.13 Ensure separate partition exists for /home (Scored) L2 L2
#1.1.14 Ensure nodev option set on /home partition (Scored) L1 L1
if sed -n '/\/home/p' /etc/fstab | grep 'nodev'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/home/s/defaults/defaults,nodev/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.15 Ensure nodev option set on /dev/shm partition (Scored) L1 L1
if sed -n '/\/dev\/shm/p' /etc/fstab | grep 'nodev'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/dev\/shm/s/defaults/defaults,nodev/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.16 Ensure nosuid option set on /dev/shm partition (Scored) L1 L1
if sed -n '/\/dev\/shm/p' /etc/fstab | grep 'nosuid'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/dev\/shm/s/defaults/defaults,nosuid/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.17 Ensure noexec option set on /dev/shm partition (Scored) L1 L1
if sed -n '/\/dev\/shm/p' /etc/fstab | grep 'noexec'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/dev\/shm/s/defaults/defaults,noexec/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
#1.1.18 Ensure nodev option set on removable media partitions (Not Scored) L1 L1
#1.1.19 Ensure nosuid option set on removable media partitions (Not Scored) L1 L1
#1.1.20 Ensure noexec option set on removable media partitions (Not Scored) L1 L1
#1.1.21 Ensure sticky bit is set on all world-writable directories (Scored) L1 L1
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
#1.1.22 Disable Automounting (Scored) L1 L2
systemctl disable autofs
########################################################################################
################################
#1.2 Configure Software Updates#
################################
#1.2.1 Ensure package manager repositories are configured (Not Scored) L1 L1
#audit: apt-cache policy
#1.2.2 Ensure GPG keys are configured (Not Scored) L1 L1
#audit: apt-key list
########################################################################################
###################################
#1.3 Filesystem Integrity Checking#
###################################
#1.3.1 Ensure AIDE is installed (Scored) L1 L1
apt-get -y install aide aide-common
aideinit
#1.3.2 Ensure filesystem integrity is regularly checked (Scored) L1 L1
echo '0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check' > /var/spool/cron/crontabs/root
########################################################################################
##########################
#1.4 Secure Boot Settings#
##########################
#1.4.1 Ensure permissions on bootloader config are configured (Scored) L1 L1
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
#1.4.2 Ensure bootloader password is set (Scored) L1 L1
echo "cat <<EOF
set superusers=\"anakin\"
password_pbkdf2 anakin grub.pbkdf2.sha512.10000.98CEB6403454C099D2A55995595519E3173D2075ACAA673F097E53789C8484B6E677E6582C3D278ACF68AD53F573E5E2BF115F97B41173C0BFB2646A597384E4.0C894BEDC392047BD3C7309FD1FD048088D53990D9B360227E7BC4FFDA37A9FB42CDD2FE263567CD5ED2A03A7EC3018233801221DE7647878949DEA4759437AE
EOF" >> /etc/grub.d/01_users
update-grub
#12345678.9 -> grub.pbkdf2.sha512.10000.98CEB6403454C099D2A55995595519E3173D2075ACAA673F097E53789C8484B6E677E6582C3D278ACF68AD53F573E5E2BF115F97B41173C0BFB2646A597384E4.0C894BEDC392047BD3C7309FD1FD048088D53990D9B360227E7BC4FFDA37A9FB42CDD2FE263567CD5ED2A03A7EC3018233801221DE7647878949DEA4759437AE
#1.4.3 Ensure authentication required for single user mode (Scored) L1 L1
#remediation: passwd root
########################################################################################
##################################
#1.5 Additional Process Hardening#
##################################
#1.5.1 Ensure core dumps are restricted (Scored) L1 L1
if grep 'hard core' /etc/security/limits.conf; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/End/ i * hard core 0' /etc/security/limits.conf; echo -e '\e[1;32mDone\e[0m'; fi
set_directive "fs.suid_dumpable" 0 "/etc/sysctl.conf";
sysctl -w fs.suid_dumpable=0
#1.5.2 Ensure XD/NX support is enabled (Not Scored) L1 L1
#audit: dmesg | grep NX
#1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored) L1 L1
set_directive "kernel.randomize_va_space" 2 "/etc/sysctl.conf";
sysctl -w kernel.randomize_va_space=2
#1.5.4 Ensure prelink is disabled (Scored) L1 L1
prelink -ua
apt-get -y remove prelink
########################################################################################
##############################
#1.6 Mandatory Access Control#
##############################
#1.6.1 Configure SELinux
#1.6.1.1 Ensure SELinux is enabled in the bootloader configuration (Scored) L2 L2
#remediation: selinux-activate
#remediation: sed -i '/^GRUB_CMDLINE_LINUX=/ c GRUB_CMDLINE_LINUX="selinux=1 security=selinux enforcing=1 audit=1"' /etc/default/grub
#remediation: update-grub
#1.6.1.2 Ensure the SELinux state is enforcing (Scored) L2 L2
#remediation: sed -i '/^SELINUX=/ c SELINUX=enforcing' /etc/selinux/config
#1.6.1.3 Ensure SELinux policy is configured (Scored) L2 L2
#remediation: sed -i '/^SELINUXTYPE=/ c SELINUXTYPE=targeted' /etc/selinux/config
#1.6.1.4 Ensure no unconfined daemons exist (Scored) L2 L2
#audit: ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'
#1.6.2.Configure AppArmor
apt-get -y install apparmor apparmor-utils
#1.6.2.1 Ensure AppArmor is enabled in the bootloader configuration (Scored) L2 L2
sed -i '/^GRUB_CMDLINE_LINUX=/ c GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"' /etc/default/grub
#1.6.2.2.Ensure all AppArmor Profiles are enforcing (Scored) L2 L2
aa-enforce /etc/apparmor.d/* 
#1.6.3 Ensure SELinux or AppArmor are installed (Scored) L2 L2
#remediation: apt-get install -y selinux-basics selinux-policy-default
#remediation: apt-get -y install apparmor apparmor-utils
########################################################################################
#####################
#1.7 Warning Banners#
#####################
#1.7.1 Command Line Warning Banners

#1.7.1.1 Ensure message of the day is configured properly (Scored) L1 L1
echo "******************************************
* This is an $COMPANY system, restricted      *
* to authorized individuals. This system *
* is subject to monitoring. By logging   *
* into this system you agree to have all *
* your communications monitored.         *
* Unauthorized users, access, and/or     *
* modification will be prosecuted.       *
******************************************" > /etc/motd
#1.7.1.2 Ensure local login warning banner is configured properly (Scored) L1 L1
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
#1.7.1.3 Ensure remote login warning banner is configured properly (Scored) L1 L1
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
#1.7.1.4 Ensure permissions on /etc/motd are configured (Scored) L1 L1
chown root:root /etc/motd
chmod 644 /etc/motd
#1.7.1.5 Ensure permissions on /etc/issue are configured (Scored) L1 L1
chown root:root /etc/issue
chmod 644 /etc/issue
#1.7.1.6 Ensure permissions on /etc/issue.net are configured (Scored) L1 L1
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
#1.7.2 Ensure GDM login banner is configured (Scored) L1 L1
#remediation: echo "[org/gnome/login-screen]
#banner-message-enable=true
#banner-message-text='Authorized uses only. Allactivity may be monitored and reported.'" >> /etc/gdm3/greeter.dconf-defaults
########################################################################################
#1.8 Ensure updates, patches, and additional security software are installed (Not Scored) L1 L1
########################################################################################
apt-get -y update
############
#2 Services#
############
########################################################################################
####################
#2.1 inetd Services#
####################
#2.1.1 Ensure xinetd is not installed (Scored) L1 L1
apt-get -y remove xinetd
apt-get -y purge xinetd
#2.1.2.Ensure openbsd-inetd is not installed (Scored) L1 L1
apt-get -y remove openbsd-inetd
########################################################################################
##############################
#2.2 Special Purpose Services#
##############################
#2.2.1 Time Synchronization
#2.2.1.1 Ensure time synchronization is in use (Not Scored) L1 L1
apt-get -y install ntp
apt-get -y install chrony
#2.2.1.2.Ensure ntp is configured (Scored) L1 L1
echo "driftfile /var/lib/ntp/ntp.drift
statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable
restrict -4 default kod nomodify notrap nopeer noquery limited
restrict -6 default kod notrap nomodify nopeer noquery limited
restrict 127.0.0.1
restrict ::1
restrict source notrap nomodify noquery
server ntp.$DOMINIO
" > /etc/ntp.conf
set_directive "RUNASUSER" "ntp" "/etc/init.d/ntp";
#2.2.1.3 Ensure chrony is configured (Scored) L1 L1
echo "server ntp.$DOMINIO
pool ntp.$DOMINIO iburst
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
hwclockfile /etc/adjtime
rtcsync
makestep 1 3" > /etc/chrony.conf

#2.2.2 Ensure X Window System is not installed (Scored) L1
apt-get -y remove xserver-xorg*
#2.2.3 Ensure Avahi Server is not enabled (Scored) L1 L1
systemctl disable avahi-daemon
#2.2.4 Ensure CUPS is not enabled (Scored) L1 L2
systemctl disable cups
#2.2.5 Ensure DHCP Server is not enabled (Scored) L1 L1
systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6
#2.2.6 Ensure LDAP server is not enabled (Scored) L1 L1
systemctl disable slapd
#2.2.7 Ensure NFS and RPC are not enabled (Scored) L1 L1
systemctl disable nfs-server
systemctl disable rpcbind
#2.2.8 Ensure DNS Server is not enabled (Scored) L1 L1
systemctl disable bind9
#2.2.9 Ensure FTP Server is not enabled (Scored) L1 L1
systemctl disable vsftpd
#2.2.10 Ensure HTTP server is not enabled (Scored) L1 L1
systemctl disable apache2
#2.2.11 Ensure IMAP and POP3 server is not enabled (Scored) L1 L1
apt-get -y remove exim4
apt-get -y purge exim4
#2.2.12 Ensure Samba is not enabled (Scored) L1 L1
systemctl disable smbd
#2.2.13 Ensure HTTP Proxy Server is not enabled (Scored) L1 L1
 systemctl disable squid
#2.2.14 Ensure SNMP Server is not enabled (Scored) L1 L1
systemctl disable snmpd
#2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored) L1 L1
file="/etc/postfix/main.cf"
if [ ! -e $file ]; then echo -e '\e[1;31m'$file' not found.\e[0m'; else sed -i /'^inet_interfaces/ c inet_interfaces = loopback-only' $file; fi
systemctl restart postfix
systemctl disable postfix
#2.2.16 Ensure rsync service is not enabled (Scored) L1 L1
systemctl disable rsync
#2.2.17 Ensure NIS Server is not enabled (Scored)...........................................................151
systemctl disable nis
########################################################################################
#####################
#2.3 Service Clients#
#####################
#2.3.1 Ensure NIS Client is not installed (Scored) L1 L1
apt-get -y remove nis
#2.3.2 Ensure rsh client is not installed (Scored) L1 L1
apt-get -y remove rsh-client rsh-redone-client
#2.3.3 Ensure talk client is not installed (Scored) L1 L1
apt-get -y remove talk
#2.3.4 Ensure telnet client is not installed (Scored) L1 L1
apt-get -y remove telnet
#2.3.5 Ensure LDAP client is not installed (Scored) L1 L1
apt-get -y remove ldap-utils
########################################################################################
#########################
#3 Network Configuration#
#########################
####################################
#3.1 Network Parameters (Host Only)#
####################################
#3.1.1 Ensure IP forwarding is disabled (Scored) L1 L1
set_directive "net.ipv4.ip_forward" 0 "/etc/sysctl.conf";
set_directive "net.ipv6.conf.all.forwarding" 0 "/etc/sysctl.conf";
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#3.1.2 Ensure packet redirect sending is disabled (Scored) L1 L1
set_directive "net.ipv4.conf.all.send_redirects" 0 "/etc/sysctl.conf";
set_directive "net.ipv4.conf.default.send_redirects" 0 "/etc/sysctl.conf";
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
##########################################
#3.2 Network Parameters (Host and Router)#
##########################################
#3.2.1 Ensure source routed packets are not accepted (Scored) L1 L1
set_directive 'net.ipv4.conf.all.accept_source_route' 0 "/etc/sysctl.conf";
set_directive 'net.ipv4.conf.default.accept_source_route' 0 "/etc/sysctl.conf";
set_directive 'net.ipv6.conf.all.accept_source_route' 0 "/etc/sysctl.conf";
set_directive 'net.ipv6.conf.default.accept_source_route' 0 "/etc/sysctl.conf";
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#3.2.2 Ensure ICMP redirects are not accepted (Scored) L1 L1
set_directive 'net.ipv4.conf.all.accept_redirects' 0 "/etc/sysctl.conf";
set_directive 'net.ipv4.conf.default.accept_redirects' 0 "/etc/sysctl.conf";
set_directive 'net.ipv6.conf.all.accept_redirects' 0 "/etc/sysctl.conf";
set_directive 'net.ipv6.conf.default.accept_redirects' 0 "/etc/sysctl.conf";
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#3.2.3 Ensure secure ICMP redirects are not accepted (Scored) L1 L1
set_directive 'net.ipv4.conf.all.secure_redirects' 0 "/etc/sysctl.conf";
set_directive 'net.ipv4.conf.default.secure_redirects' 0 "/etc/sysctl.conf";
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.2.4 Ensure suspicious packets are logged (Scored) L1 L1
set_directive 'net.ipv4.conf.all.log_martians' 1 "/etc/sysctl.conf";
set_directive 'net.ipv4.conf.default.log_martians' 1 "/etc/sysctl.conf";
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
#3.2.5 Ensure broadcast ICMP requests are ignored (Scored) L1 L1
set_directive 'net.ipv4.icmp_echo_ignore_broadcasts' 1 "/etc/sysctl.conf";
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
#3.2.6 Ensure bogus ICMP responses are ignored (Scored) L1 L1
set_directive 'net.ipv4.icmp_ignore_bogus_error_responses' 1 "/etc/sysctl.conf";
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
#3.2.7 Ensure Reverse Path Filtering is enabled (Scored) L1 L1
set_directive 'net.ipv4.conf.all.rp_filter' 1 "/etc/sysctl.conf";
set_directive 'net.ipv4.conf.default.rp_filter' 1 "/etc/sysctl.conf";
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
#3.2.8 Ensure TCP SYN Cookies is enabled (Scored) L1 L1
set_directive 'net.ipv4.tcp_syncookies' 1 "/etc/sysctl.conf";
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
#3.2.9 Ensure IPv6 router advertisements are not accepted (Scored) L1 L1
set_directive 'net.ipv6.conf.all.accept_ra' 0 "/etc/sysctl.conf";
set_directive 'net.ipv6.conf.default.accept_ra' 0 "/etc/sysctl.conf";
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
##################
#3.3 TCP Wrappers#
##################
#3.3.1 Ensure TCP Wrappers is installed (Scored) L1 L1
apt-get -y install tcpd
#3.3.2 Ensure /etc/hosts.allow is configured (Not Scored) L1 L1
if grep "$HOSTS_ALLOWED" /etc/hosts.allow; then echo "Ya esta configurado."; else echo "ALL: $HOSTS_ALLOWED" >> /etc/hosts.allow; fi
#3.3.3 Ensure /etc/hosts.deny is configured (Not Scored) L1 L1
if grep "ALL: ALL" /etc/hosts.deny; then echo "Ya esta configurado."; else echo "ALL: ALL" >> /etc/hosts.deny; fi
#3.3.4 Ensure permissions on /etc/hosts.allow are configured (Scored) L1 L1
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
#3.3.5 Ensure permissions on /etc/hosts.deny are configured (Scored) L1 L1
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny
################################
#3.4 Uncommon Network Protocols#
################################
#3.4.1 Ensure DCCP is disabled (Not Scored) L1 L1
echo 'install dccp /bin/true' > /etc/modprobe.d/dccp.conf
#3.4.2 Ensure SCTP is disabled (Not Scored) L1 L1
echo 'install sctp /bin/true' > /etc/modprobe.d/sctp.conf
#3.4.3 Ensure RDS is disabled (Not Scored) L1 L1
echo 'install rds /bin/true' > /etc/modprobe.d/rds.conf
#3.4.4 Ensure TIPC is disabled (Not Scored) L1 L1
echo 'install tipc /bin/true' > /etc/modprobe.d/tipc.conf
############################
#3.5 Firewall Configuration#
############################
#3.5.1 Configure IPv4 iptables
#iptables -F
# Ensure default deny firewall policy
#iptables -P INPUT DROPiptables -P OUTPUT DROP
#iptables -P FORWARD DROP
# Ensure loopback traffic is configured
#iptables -A INPUT -i lo -j ACCEPTiptables -A OUTPUT -o lo -j ACCEPT
#iptables -A INPUT -s 127.0.0.0/8 -j DROP
# Ensure outbound and established connections are configured
#iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p udp -m state--state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 22) connections
#iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
#3.5.1.1 Ensure default deny firewall policy (Scored) L1 L1
#iptables -P INPUT DROP
#iptables -P OUTPUT DROP
#iptables -P FORWARD DROP
#3.5.1.2.Ensure loopback traffic is configured (Scored) L1 L1
#iptables -A INPUT -i lo -j ACCEPT
#iptables -A OUTPUT -o lo -j ACCEPT
#iptables -A INPUT -s 127.0.0.0/8 -j DROP
#3.5.1.3 Ensure outbound and established connections are configured (Not Scored) L1 L1
#iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT -p udp -m state --state ESTABLISHED -jACCEPT
#iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
#3.5.1.4 Ensure firewall rules exist for all open ports (Scored) L1 L1
#iptables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT
#3.5.2.Configure IPv6 ip6tables
#ip6tables -F
# Ensure default deny firewall policy
#ip6tables -P INPUT DROP
#ip6tables -P OUTPUT DROP
#ip6tables -P FORWARD DROP
# Ensure loopback traffic is configured
#ip6tables -A INPUT -i lo -j ACCEPT
#ip6tables -A OUTPUT -o lo -j ACCEPT
#ip6tables -A INPUT -s ::1 -j DROP
# Ensure outbound and established connections are configured
#ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
#ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 22) connections
#ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
#3.5.2.1 Ensure IPv6 default deny firewall policy (Scored) L1 L1
#ip6tables -P INPUT DROP
#ip6tables -P OUTPUT DROP
#ip6tables -P FORWARD DROP
#3.5.2.2.Ensure IPv6 loopback traffic is configured (Scored) L1 L1
#ip6tables -A INPUT -i lo -j ACCEPT
#ip6tables -A OUTPUT -o lo -j ACCEPT
#ip6tables -A INPUT -s ::1 -j DROP
#3.5.2.3 Ensure IPv6 outbound and established connections are configured (Not Scored) L1 L1
#iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT -p udp -m state --state ESTABLISHED -jACCEPT
#iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
#3.5.2.4 Ensure IPv6 firewall rules exist for all open ports (Not Scored) L1 L1
#ip6tables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT
#3.5.3 Ensure iptables is installed (Scored) L1 L1
apt-get install iptables
#3.6 Ensure wireless interfaces are disabled (Not Scored) L1 L2
#ip link set <interface> down
#3.7 Disable IPv6 (Not Scored) L2 L2
add_string 'GRUB_CMDLINE_LINUX="' "ipv6.disable=1 " "/etc/default/grub"
update-grub
########################
#4.Logging and Auditing#
########################
##########################################
#4.1 Configure System Accounting (auditd)#
##########################################
#4.1.1 Configure Data Retention
#4.1.1.1 Ensure audit log storage size is configured (Not Scored) L2 L2
set_directive "max_log_file " "1024" "/etc/audit/auditd.conf"

#4.1.1.2 Ensure system is disabled when audit logs are full (Scored) L2 L2
set_directive "space_left_action " "email" "/etc/audit/auditd.conf"
set_directive "action_mail_acct " "root" "/etc/audit/auditd.conf"
set_directive "admin_space_left_action " "halt" "/etc/audit/auditd.conf"
#4.1.1.3 Ensure audit logs are not automatically deleted (Scored) L2 L2
set_directive "max_log_file_action " "keep_logs" "/etc/audit/auditd.conf"
#4.1.2 Ensure auditd service is enabled (Scored) L2 L2
systemctl enable auditd
#4.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored) L2 L2
add_string 'GRUB_CMDLINE_LINUX="' "audit=1 " "/etc/default/grub"
update-grub
#4.1.4 Ensure events that modify date and time information are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change" > /etc/audit/audit.rules
#4.1.5 Ensure events that modify user/group information are collected (Scored) L2 L2
echo "-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
#4.1.6 Ensure events that modify the system's network environment are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale" >> /etc/audit/audit.rules
#4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (Scored) L2 L2
#echo "-w /etc/selinux/ -p wa -k MAC-policy
#-w /usr/share/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
#4.1.8 Ensure login and logout events are collected (Scored) L2 L2
echo "-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins" >> /etc/audit/audit.rules
#4.1.9 Ensure session initiation information is collected (Scored) L2 L2
echo "-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins" >> /etc/audit/audit.rules
#4.1.10 Ensure discretionary access control permission modification events are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
#4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (Scored) L2 L2
echo "--a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
#4.1.12 Ensure use of privileged commands is collected (Scored) L2 L2
find  -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules
#4.1.13 Ensure successful file system mounts are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
#4.1.14 Ensure file deletion events by users are collected (Scored) L2 L2
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
#4.1.15 Ensure changes to system administration scope (sudoers) is collected (Scored) L2 L2
echo "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/audit.rules
#4.1.16 Ensure system administrator actions (sudolog) are collected (Scored) L2 L2
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
#4.1.17 Ensure kernel module loading and unloading is collected (Scored) L2 L2
echo "-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules
#4.1.18 Ensure the audit configuration is immutable (Scored) L2 L2
echo "-e 2" >> /etc/audit/rules.d/audit.rules
#######################
#4.2 Configure Logging#
#######################
#4.2.1 Configure rsyslog
#4.2.1.1 Ensure rsyslog Service is enabled (Scored) L1 L1
apt-get -y install rsyslog
systemctl enable rsyslog
#4.2.1.2 Ensure logging is configured (Not Scored) L1 L1
add_string 'auth,user.* ' "/var/log/messages" "/etc/rsyslog.conf"
add_string 'kern.* ' "/var/log/kern.log" "/etc/rsyslog.conf"
add_string 'daemon.* ' "/var/log/daemon.log" "/etc/rsyslog.conf"
add_string 'syslog.* ' "/var/log/syslog" "/etc/rsyslog.conf"
add_string 'lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* ' "/var/log/unused.log" "/etc/rsyslog.conf"
#4.2.1.3 Ensure rsyslog default file permissions configured (Scored) L1 L1
add_string '$FileCreateMode ' "0640" "/etc/rsyslog.conf"
#4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored) L1 L1
replace_line "#*.* @@remote-host:514" "*.* @@$DOMINIO:5146" "/etc/rsyslog.conf"
pkill -HUP rsyslogd
#4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored) L1 L1
#Solo aplica si el servidor es un servidor de logs.
#remediation: replace_line "#\$ModLoad imtcp" "\$ModLoad imtcp" "/etc/rsyslog.conf"
#remediation: replace_line "#\$InputTCPServerRun 514" "\$InputTCPServerRun 514" "/etc/rsyslog.conf"
#remediation: pkill -HUP rsyslogd
#4.2.2.Configure syslog-ng
#4.2.2.1 Ensure syslog-ng service is enabled (Scored) L1 L1
#remediation: update-rc.d syslog-ng enable
#4.2.2.2 Ensure logging is configured (Not Scored) L1 L1
#4.2.2.3 Ensure syslog-ng default file permissions configured (Scored) L1 L1
#4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host (Not Scored) L1 L1
#4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored) L1 L1
#4.2.3 Ensure rsyslog or syslog-ng is installed (Scored) L1 L1
apt-get -y install rsyslog
apt-get -y remove syslog-ng
#4.2.4 Ensure permissions on all logfiles are configured (Scored) L1 L1
chmod -R g-wx,o-rwx /var/log/*
#4.3 Ensure logrotate is configured (Not Scored) L1 L1
########################################################################################
############################################
#5 Access, Authentication and Authorization#
############################################
####################
#5.1 Configure cron#
####################
#5.1.1 Ensure cron daemon is enabled (Scored) L1 L1
systemctl enable cron
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
rm /etc/cron.deny
rm /etc/at.deny
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
#5.2.2 Ensure permissions on SSH private host key files are configured (Scored) L1 L1
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;
#5.2.3 Ensure permissions on SSH public host key files are configured (Scored) L1 L1
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
#5.2.4 Ensure SSH Protocol is set to 2 (Scored) L1 L1
add_string "Protocol " "2" "/etc/ssh/sshd_config"
#5.2.5 Ensure SSH LogLevel is set to INFO (Scored) L1 L1
sed -i '/^#LogLevel/ c LogLevel INFO' /etc/ssh/sshd_config
#5.2.6 Ensure SSH X11 forwarding is disabled (Scored) L1 L2
sed -i '/^X11Forwarding/ c X11Forwarding no' /etc/ssh/sshd_config
#5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored) L1 L1
sed -i '/^#MaxAuthTries/ c MaxAuthTries 4' /etc/ssh/sshd_config
#5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored) L1 L1
sed -i '/^#IgnoreRhosts/ c IgnoreRhosts yes' /etc/ssh/sshd_config
#5.2.9 Ensure SSH HostbasedAuthentication is disabled (Scored) L1 L1
sed -i '/^#HostbasedAuthentication/ c HostbasedAuthentication no' /etc/ssh/sshd_config
#5.2.10 Ensure SSH root login is disabled (Scored) L1 L1
sed -i '/^#PermitRootLogin/ c PermitRootLogin no' /etc/ssh/sshd_config
#5.2.11 Ensure SSH PermitEmptyPasswords is disabled (Scored) L1 L1
sed -i '/^#PermitEmptyPasswords/ c PermitEmptyPasswords no' /etc/ssh/sshd_config
#5.2.12 Ensure SSH PermitUserEnvironment is disabled (Scored) L1 L1
sed -i '/^#PermitUserEnvironment/ c PermitUserEnvironment no' /etc/ssh/sshd_config
#5.2.13 Ensure only strong ciphers are used (Scored)
add_string "Ciphers " "aes128-ctr,aes192-ctr,aes256-ctr" "/etc/ssh/sshd_config"
#5.2.14 Ensure only approved MAC algorithms are used (Scored) L1 L1
add_string "MACs " "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" "/etc/ssh/sshd_config"
#5.2.15.Ensure only strong Key Exchange algorithms are used (Scored) L1 L1
add_string "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" "/etc/ssh/sshd_config"
#5.2.16 Ensure SSH Idle Timeout Interval is configured (Scored) L1 L1
sed -i '/^#ClientAliveInterval/ c ClientAliveInterval 300' /etc/ssh/sshd_config
sed -i '/^#ClientAliveCountMax/ c ClientAliveCountMax 0' /etc/ssh/sshd_config
#5.2.17 Ensure SSH LoginGraceTime is set to one minute or less (Scored) L1 L1
sed -i '/^#LoginGraceTime/ c LoginGraceTime 60' /etc/ssh/sshd_config
#5.2.18 Ensure SSH access is limited (Scored) L1 L1
add_string "AllowUsers " "$ADMIN_USER" "/etc/ssh/sshd_config"
add_string "AllowGroups " "$ADMIN_USER" "/etc/ssh/sshd_config"
add_string "DenyUsers " "ALL" "/etc/ssh/sshd_config"
add_string "DenyGroups " "ALL" "/etc/ssh/sshd_config"
#5.2.17 Ensure SSH warning banner is configured (Scored) L1 L1
sed -i '/^#Banner/ c Banner \/etc\/issue.net' /etc/ssh/sshd_config
systemctl reload sshd
###################
#5.3 Configure PAM#
###################
#5.3.1 Ensure password creation requirements are configured (Scored) L1 L1
apt-get -y install libpam-pwquality
#vi /etc/pam.d/common-password
#++ password requisite pam_pwquality.so retry=3
sed -i '/^# minlen =/ c minlen = 14' /etc/security/pwquality.conf
sed -i '/^# dcredit =/ c dcredit = -1' /etc/security/pwquality.conf
sed -i '/^# ucredit =/ c ucredit = -1' /etc/security/pwquality.conf
sed -i '/^# ocredit =/ c ocredit = -1' /etc/security/pwquality.conf
sed -i '/^# lcredit =/ c lcredit = -1' /etc/security/pwquality.conf
#5.3.2 Ensure lockout for failed password attempts is configured (Scored) L1 L1
#vi /etc/pam.d/common-auth
#++ auth required pam_tally2.so onerr=failaudit silent deny=5 unlock_time=900
#5.3.3 Ensure password reuse is limited (Scored) L1 L1
#vi /etc/pam.d/common-password
#++ password required pam_pwhistory.so remember=5
#5.3.4 Ensure password hashing algorithm is SHA-512 (Scored) L1 L1
#vi/etc/pam.d/common-password
#++ password [success=1 default=ignore] pam_unix.so sha512
###################################
#5.4 User Accounts and Environment#
###################################
#5.4.1 Set Shadow Password Suite Parameters
#5.4.1.1 Ensure password expiration is 365 days or less (Scored) L1 L1
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -I % chage --maxdays 90 %
#5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored) L1 L1
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -I % chage --mindays 7 %
#5.4.1.3 Ensure password expiration warning days is 7 or more (Scored) L1 L1
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -I % chage --warndays 7 %
#5.4.1.4 Ensure inactive password lock is 30 days or less (Scored) L1 L1
useradd -D -f 30
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | grep -v "root" | grep -v "$ADMIN_USER" | xargs -I % chage --inactive 30 %
#5.4.1.5 Ensure all users last password change date is in the past (Scored) L1 L1
#5.4.2 Ensure system accounts are non-login (Scored) L1 L1
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}' | xargs egrep -I % usermod -s /sbin/nologin %
#5.4.3 Ensure default group for the root account is GID 0 (Scored) L1 L1
usermod -g 0 root
#5.4.4 Ensure default user umask is 027 or more restrictive (Scored) L1 L1
sed -i 's/umask 0.*$/umask 027/' /etc/bash.bashrc
sed -i 's/umask 0.*$/umask 027/' /etc/profile /etc/profile.d/*.sh
#5.4.5 Ensure default user shell timeout is 900 seconds or less (Scored) L2 L2
#vi /etc/bashrc
#vi /etc/profile /etc/profile.d/*.sh
#TMOUT=600
#5.5 Ensure root login is restricted to system console (Not Scored) L1 L1
if [ ! -e /etc/securetty.orig ]; then cp /etc/securetty /etc/securetty.orig; echo -e "console\ntty4" > /etc/securetty; fi
#5.6 Ensure access to the su command is restricted (Scored) L1 L1
#vi /etc/pam.d/su
#++ auth required pam_wheel.so
#vi /etc/group
#++ sudo:x:10:root,<user list>
######################
#6.System Maintenance#
######################
#############################
#6.1 System File Permissions#
#############################
#6.1.1 Audit system file permissions (Not Scored) L2 L2
#6.1.2 Ensure permissions on /etc/passwd are configured (Scored) L1 L1
chown root:root /etc/passwd
chmod 644 /etc/passwd
#6.1.3 Ensure permissions on /etc/shadow are configured (Scored) L1 L1
chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow
#6.1.4 Ensure permissions on /etc/group are configured (Scored) L1 L1
chown root:root /etc/group
chmod 644 /etc/group
#6.1.5 Ensure permissions on /etc/gshadow are configured (Scored) L1 L1
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow
#6.1.6 Ensure permissions on /etc/passwd- are configured (Scored) L1 L1
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-
#6.1.7 Ensure permissions on /etc/shadow- are configured (Scored) L1 L1
chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-
#6.1.8 Ensure permissions on /etc/group- are configured (Scored) L1 L1
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-
#6.1.9 Ensure permissions on /etc/gshadow- are configured (Scored) L1 L1
chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-
#6.1.10 Ensure no world writable files exist (Scored) L1 L1
#6.1.11 Ensure no unowned files or directories exist (Scored) L1 L1
#6.1.11 Ensure no ungrouped files or directories exist (Scored) L1 L1
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
#6.2.20 Ensure shadow group is empty (Scored) L1 L1
########################################################################################
echo "
HISTFILESIZE=1000000
HISTSIZE=1000000
HISTTIMEFORMAT='%F %T '
PROMPT_COMMAND='history -a'" >> /root/.bashrc
########################################################################################
