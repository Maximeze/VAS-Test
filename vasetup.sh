#!/bin/bash

VERSION="1.00"
LOGFILENAME="vasetup.log"

U16WALLETLINK="https://github.com/VelumPlatform/VelumPlatform/releases/download/v0.1/linux-nongui.zip" 	
WALLETDIR="velum"
DATADIRNAME=".velumcore"
CONFFILENAME="velum.conf"
DAEMONFILE="velumd"
CLIFILE="velum-cli"
P2PPORT="17500"
RPCPORT="18092"
COLLAMOUNT="1000"
TICKER="VLM"

function print_welcome() {
	echo ""
	echo "###############################################################################"
	echo "###                                                                         ###"
	echo "###                      Velum masternode autosetup script                  ###"
	echo "###                                                                         ###"
	echo "###                                Version: ${VERSION}                            ###"
	echo "###                                                                         ###"
	echo "###############################################################################"
	echo

}

function run_questionnaire() {
	if ! [ "$USER" = "root" ]; then
		echo -en " Checking sudo permissions \r"
		sudo lsb_release -a &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		echo -en " Checking sudo permissions \r"
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    sudo permissions check [Successful]" >>${LOGFILE} || echo "#    sudo permissions check [FAILED]" >>${LOGFILE}

		if [ $ec -gt 0 ]; then
			echo -en " ${RED}Failed to get sudo permissions, installation script aborted ${NC}\n"
			exit
		fi
	fi

	echo
	echo "###      SYSTEM PREPARATION PART     ###"
	## System update
	echo
	sysupdate=1
	echo

	# detecting current swap size
	curswapmb=$(free -m | grep Swap | grep -oE 'Swap: +[0-9]+ ' | grep -oE '[0-9]+')
	
	if [ $curswapmb -gt 0 ]; then
		swapfilename=$(sudo more /etc/fstab | grep -v '#' | grep swap | grep -oE '^.+ +none' | grep -oE '^.+ ')
        echo "#    Existing SWAP detected: size=${curswapmb}MB; filename=${swapfilename} Swap creation skipped." >>${LOGFILE} 
        echo "Current swap size is ${curswapmb}MB. Script will not create additional swap."    
		
		createswap=0
	else

		swapsizegigs=2
		echo " SWAP file size will be set to ${swapsizegigs}GB"
		createswap=1	
	fi
	echo

	## Fail2Ban installation
	
	setupfail2ban=1

	echo

	## ufw activation
	ufwstatus=$(sudo ufw status | grep -oE '(active|inactive)')
	if [ "$ufwstatus" = "active" ]; then
		echo "Ubuntu firewall 'ufw' already activated"
		echo "#    Ubuntu firewall 'ufw' already activated" >>${LOGFILE}
		p2pufw=$(sudo ufw status | grep -oE ^${P2PPORT}/tcp)
		[ "$p2pufw" = "" ] && p2pufwadd=1 || p2pufwadd=0
		[ $p2pufwadd -eq 1 ] && echo " P2P tcp port '${P2PPORT}' will be added to the list of allowed" || echo " P2P tcp port '${P2PPORT}' already in the list of allowed"
		[ $p2pufwadd -eq 1 ] && echo "#    P2P tcp port '${P2PPORT}' will be added to the list of allowed" >>${LOGFILE} || echo "#    P2P tcp port '${P2PPORT}' already in the list of allowed" >>${LOGFILE}

		rpcufw=$(sudo ufw status | grep -oE ^${RPCPORT}/tcp)
		if [ "$rpcufw" = "" ]; then
			rpcufwadd=1;
		else
			echo " RPC tcp port '${RPCPORT}' already in the list of allowed"
			echo "#    RPC tcp port '${RPCPORT}' already in the list of allowed" >>${LOGFILE}
			rpcufwadd=0
		fi
		if [ $rpcufwadd -eq 1 ] || [ $p2pufwadd -eq 1 ]; then setupufw=2; else setupufw=0; fi
	else
		setupufw=1;

		if [ $setupufw -eq 1 ]; then
			echo " P2P tcp port '${P2PPORT}' will be added to the list of allowed"
			echo " RPC tcp port '${RPCPORT}' will be added to the list of allowed"
			p2pufwadd=1
			rpcufwadd=1;

			#show list of listening ports
			tcp4ports=$(netstat -ln | grep 'LISTEN ' | grep 'tcp ' | grep -oE '0.0.0.0:[0-9]+' | grep -oE ':[0-9]+' | grep -oE '[0-9]+')
			if ! [ "$tcp4ports" = "" ]; then
				echo
				echo " Following tcp ports currently LISTENING and will be added to list of allowed:"
				while read -r tcp4port; do
					echo -en "  ${PURPLE}+ $tcp4port ${NC}\n"
					portlist+=($tcp4port)
				done <<<$tcp4ports
			fi

			setupufw=1
				
		fi
	fi
	echo

	## New user creation
	
		createuser=1
		
		newsudouser=1
		if [ "$USER" = "root" ]; then
			sudowopass=1;
		fi

		newuser="smaxime";
		echo "#      New username: ${newuser}" >>${LOGFILE}
		echo -en "${GREEN}  Smaxime ${NC}\n"
		#echo -en "${PURPLE}  NOTE: There will be no character substitution entering password, just type it!${NC}\n" && echo
		read -sp '  Enter password: ' pwd1 && echo
		read -sp '  Confirm password: ' pwd2 && echo

		if [ "$pwd1" = "$pwd2" ] && ! [ "$pwd1" = "" ]; then
			ePass=$(perl -e "print crypt('${pwd1}', '${newuser}')")
			pwd1=""
			pwd2=""
			echo " Password accepted, password hash: "$ePass
			echo "#   Password accepted, password hash: "$ePass >>${LOGFILE}
		else
			echo
			echo -en "${RED}  WARNING: Passwords not equal or empty, please try one more time. ${NC}\n"
			echo
			echo "#    WARNING: Passwords not equal or empty, please try one more time. " >>${LOGFILE}
			read -sp '  Enter password: ' pwd1 && echo
			read -sp '  Confirm password: ' pwd2 && echo
			if [ "$pwd1" = "$pwd2" ] && ! [ "$pwd1" = "" ]; then
				ePass=$(perl -e "print crypt('${pwd1}', '${newuser}')")
				pwd1=""
				pwd2=""
				echo " Password accepted, password hash: "$ePass
				echo "#   Password accepted, password hash: "$ePass >>${LOGFILE}
			else
				echo -en "${RED} WARNING: Something wrong with passwords, skipping user creation.${NC}\n"
				echo "#    WARNING: Something wrong with passwords, skipping user creation." >>${LOGFILE}
				createuser=0
			fi
		fi
	echo
	echo

	echo "###    MASTERNODE PREPARATION PART   ###"
	## Wallet installation
	echo
	
	setupwallet=1	
	loadonboot=1
		
	echo
	## Masternode setup

		setupmn=1

		vpsip=$(dig +short myip.opendns.com @resolver1.opendns.com)

		if ! [[ $vpsip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then vpsip="a.b.c.d"; fi
		echo "#    Detected ip address: ${vpsip}" >>${LOGFILE}
		echo
		read -p " Please provide VPS external IP address or accept detected with ENTER [${vpsip}]: " vpsiptxt && echo
		echo "#    Entered ip address: ${vpsiptxt}" >>${LOGFILE}
		if [[ $vpsiptxt =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			vpsip=$vpsiptxt

		elif ! [[ $vpsip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! [[ $vpsiptxt =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			vpsip=""
			setupmn=0
			echo -en "${RED}   ERROR: Invalid ip address provided, masternode setup will be aborted.${NC}\n"
		fi

		read -p " Please provide RPC user name (can be any of you like): " rpcuser
		echo "#    Entered rpcuser: ${rpcuser}" >>${LOGFILE}

		read -p " Please provide RPC password (letters and numbers): " rpcpassword
		echo
		echo "#    Entered rpcpassword: ****" >>${LOGFILE} #not recording for security reasons

		read -p " Please provide masternode private key (genkey): " mnprivkey
		echo "#    Entered mnprivkey: ${mnprivkey}" >>${LOGFILE}

		read -p " Please provide collateral tx hash (txhash): " txhash
		echo "#    Entered txhash: ${txhash}" >>${LOGFILE}

		read -p " Please provide collateral tx output (txoutput): " txoutput
		echo "#    Entered txoutput: ${txoutput}" >>${LOGFILE}
		echo

	echo
	echo
	echo "     PLEASE REVIEW ANSWERS ABOVE   "
	read -n1 -p "     Press any key to start installation of Ctrl+C to exit   "

}

function create_swap() {
	# create swap file [0.20]
	ec=0
	echo "CREATING SWAP FILE"
	echo >>${LOGFILE}
	echo "###  SWAP creation started  ###" >>${LOGFILE}
	free -h &>>${LOGFILE}
	echo -en " Creating /swapfile of ${swapsizegigs}GB size \r"
	sudo fallocate -l ${swapsizegigs}G /swapfile &>>${LOGFILE}
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	[ $ec -eq 0 ] && echo "#    fallocate -l ${swapsizegigs}G /swapfile [Successful]" >>${LOGFILE} || echo "#    fallocate -l ${swapsizegigs}G /swapfile [FAILED]" >>${LOGFILE}

	if [ $ec -eq 0 ]; then
		echo -en " Changing permissions of /swapfile \r"
		sudo chmod 600 /swapfile &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    chmod 600 /swapfile [Successful]" >>${LOGFILE} || echo "#    chmod 600 /swapfile [FAILED]" >>${LOGFILE}
	fi
	if [ $ec -eq 0 ]; then
		echo -en " Setting /swapfile type to swap \r"
		sudo mkswap /swapfile &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    mkswap /swapfile [Successful]" >>${LOGFILE} || echo "#    mkswap /swapfile [FAILED]" >>${LOGFILE}
	fi
	if [ $ec -eq 0 ]; then
		echo -en " Switching on /swapfile swap \r"
		sudo swapon /swapfile &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    swapon /swapfile [Successful]" >>${LOGFILE} || echo "#    swapon /swapfile [FAILED]" >>${LOGFILE}
	fi
	if [ $ec -eq 0 ]; then
		echo -en " Updating /etc/sysctl.conf \r"
		sudo sh -c "echo  >> /etc/sysctl.conf" &>>${LOGFILE}
		sudo sh -c "echo 'vm.swappiness=10' >> /etc/sysctl.conf" &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    Updating /etc/sysctl.conf [Successful]" >>${LOGFILE} || echo "#    Updating /etc/sysctl.conf [FAILED]" >>${LOGFILE}
	fi
	if [ $ec -eq 0 ]; then
		echo -en " Updating /etc/fstab \r"
		sudo sh -c "echo >> /etc/fstab" &>>${LOGFILE}
		sudo sh -c "echo '/swapfile   none    swap    sw    0   0' >> /etc/fstab" &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    Updating /etc/fstab [Successful]" >>${LOGFILE} || echo "#    Updating /etc/fstab [FAILED]" >>${LOGFILE}
	fi

	free -h &>>${LOGFILE}
	echo "###  SWAP creation complete  ###" >>${LOGFILE}
	echo
}

function detect_osversion() {
	osver=$(lsb_release -c | grep -oE '[^[:space:]]+$')
}

function setup_fail2ban() {
	# setup fail2ban [0.20]
	echo "INSTALLING FAIL2BAN INTRUSION PROTECTION"
	echo >>${LOGFILE}
	echo "###  Fail2Ban installation started  ###" >>${LOGFILE}
	ec=0

	echo -en " Downloading and instaling Fail2ban application \r"
	sudo apt-get -y install fail2ban &>>${LOGFILE}
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	[ $ec -eq 0 ] && echo "#    Installation of fail2ban [Successful]" >>${LOGFILE} || echo "#    Installation of fail2ban [FAILED]" >>${LOGFILE}

	if [ $ec -eq 0 ]; then
		echo -en " Enabling Fail2ban service autostart \r"
		sudo systemctl enable fail2ban &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    Enabling Fail2ban service autostart [Successful]" >>${LOGFILE} || echo "#    Enabling Fail2ban service autostart [FAILED]" >>${LOGFILE}
	fi
	if [ $ec -eq 0 ]; then
		echo -en " Starting Fail2ban service \r"
		sudo systemctl start fail2ban &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    Starting Fail2ban service [Successful]" >>${LOGFILE} || echo "#    Starting Fail2ban service [FAILED]" >>${LOGFILE}
	fi
	echo "###  Fail2Ban installation complete  ###" >>${LOGFILE}
	echo

}

function setup_ufw() {
	echo "CONFIGURING UFW FIREWALL"
	echo >>${LOGFILE}
	echo "###  Setup of ufw started  ###" >>${LOGFILE}
	ec=0
	if [ $setupufw -eq 1 ]; then
		#newly activate ufw

		# disallow everything except ssh and masternode inbound ports
		echo -en " Adding 'default deny' rule \r"
		sudo ufw default deny &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    sudo ufw default deny [Successful]" >>${LOGFILE} || echo "#    sudo ufw default deny [FAILED]" >>${LOGFILE}

		echo -en " Switching ufw logging on \r"
		sudo ufw logging on &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    sudo ufw logging on [Successful]" >>${LOGFILE} || echo "#    sudo ufw logging on [FAILED]" >>${LOGFILE}

		#add listening ports
		if [ ${#portlist[@]} -gt 0 ]; then
			for port in "${portlist[@]}"; do
				echo -en " Adding port ${port} to allowed list \r"
				sudo ufw allow $port/tcp &>>${LOGFILE}
				[ $? -eq 0 ] && ec=0 || ec=1
				[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
				[ $ec -eq 0 ] && echo "#    sudo ufw allow ${port}/tcp [Successful]" >>${LOGFILE} || echo "#    sudo ufw allow ${port}/tcp [FAILED]" >>${LOGFILE}
			done
		fi

		#add p2p port
		echo -en " Adding P2P port ${P2PPORT} to allowed list \r"
		sudo ufw allow $P2PPORT/tcp &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    sudo ufw allow ${P2PPORT}/tcp [Successful]" >>${LOGFILE} || echo "#    sudo ufw allow ${P2PPORT}/tcp [FAILED]" >>${LOGFILE}

		#add rpc port
		if [ $rpcufwadd -eq 1 ]; then
			echo -en " Adding RPC port ${RPCPORT} to allowed list \r"
			sudo ufw allow $RPCPORT/tcp &>>${LOGFILE}
			[ $? -eq 0 ] && ec=0 || ec=1
			[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
			[ $ec -eq 0 ] && echo "#    sudo ufw allow ${RPCPORT}/tcp [Successful]" >>${LOGFILE} || echo "#    sudo ufw allow ${RPCPORT}/tcp [FAILED]" >>${LOGFILE}
		fi

		# This will only allow 6 connections every 30 seconds from the same IP address.
		echo -en " Adding limits for SSH \r"
		sudo ufw limit OpenSSH &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    sudo ufw limit OpenSSH [Successful]" >>${LOGFILE} || echo "#    sudo ufw limit OpenSSH [FAILED]" >>${LOGFILE}

		#enabling ufw
		echo -en " Enabling ufw \r"
		sudo ufw --force enable &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    sudo ufw --force enable [Successful]" >>${LOGFILE} || echo "#    sudo ufw --force enable [FAILED]" >>${LOGFILE}

	elif [ $setupufw -eq 2 ]; then
		#add ports to active ufw
		if [ $p2pufwadd -eq 1 ]; then
			echo -en " Adding P2P port ${P2PPORT} to allowed list \r"
			sudo ufw allow $P2PPORT/tcp &>>${LOGFILE}
			[ $? -eq 0 ] && ec=0 || ec=1
			[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
			[ $ec -eq 0 ] && echo "#    sudo ufw allow ${P2PPORT}/tcp [Successful]" >>${LOGFILE} || echo "#    sudo ufw allow ${P2PPORT}/tcp [FAILED]" >>${LOGFILE}
		fi
		if [ $rpcufwadd -eq 1 ]; then
			echo -en " Adding RPC port ${RPCPORT} to allowed list \r"
			sudo ufw allow $RPCPORT/tcp &>>${LOGFILE}
			[ $? -eq 0 ] && ec=0 || ec=1
			[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
			[ $ec -eq 0 ] && echo "#    sudo ufw allow ${RPCPORT}/tcp [Successful]" >>${LOGFILE} || echo "#    sudo ufw allow ${RPCPORT}/tcp [FAILED]" >>${LOGFILE}
		fi

	fi
	echo
}

function system_update() {
	#system update [0.20]
	echo "UPDATING SYSTEM PACKAGES"
	echo >>${LOGFILE}
	echo "###   Update of system package started  ###" >>${LOGFILE}
	ec=0

	echo -en " Updating repositories \r"
	sudo apt-get update -y &>>${LOGFILE}
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1

	echo -en " Updating packages, please wait \r"
	sudo apt-get upgrade -y &>>${LOGFILE}
	[ $? -eq 0 ] && ec=0 || ec=1
	echo -en " Updating packages              \r"
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	[ $ec -eq 0 ] && echo "#    Update of system package complete successfully" >>${LOGFILE} || echo "#    Update of system package complete with ERRORS" >>${LOGFILE}
	echo "###  Update of system package complete  ###" >>${LOGFILE}
	echo
}

function setup_wallet() {
	#install pre-requisites
	install_prerequisites
	download_wallet

}

function install_prerequisites() {
	#wallet pre-requisites [0.20]
	echo "INSTALLING PRE-REQUISITE PACKAGES"
	echo >>${LOGFILE}
	echo "###    Pre-requisite installation started    ###" >>${LOGFILE}
	ec=0
	if [ $osver = "xenial" ]; then
		#install Ubuntu 16.04 pre-requisites
		echo -en " Adding new repository \r"
		sudo add-apt-repository -y ppa:bitcoin/bitcoin >>${LOGFILE} 2>&1
		[ $? -eq 0 ] && ec=0 || ec=1
		sleep 1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		echo -en " Installing required packages \r"
        sudo apt-get update -y >>${LOGFILE} 2>&1
		sudo apt-get install unzip curl build-essential libtool autotools-dev libssl-dev libevent-dev bsdmainutils libboost-all-dev software-properties-common libzmq3-dev libminiupnpc-dev libdb4.8-dev libdb4.8++-dev -y >>${LOGFILE} 2>&1
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	fi
	echo "###    Pre-requisite installation complete    ###" >>${LOGFILE}
	echo
}

function download_wallet() {
	#wallet download [0.30]
	echo "DOWNLOADING AND INSTALLING WALLET"
	echo >>${LOGFILE}
	echo "###    Downloading wallet started    ###" >>${LOGFILE}
	ec=0

	echo -en " Installing unzip package \r"
	sudo apt-get install -y unzip &>>${LOGFILE}
	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	
	if [ ! -d "${HOME}/${WALLETDIR}" ]; then
		echo "#      Creating wallet directory" >>${LOGFILE}
		echo -ne " Creating wallet directory \r"
		if [ $newusermn -eq 1 ]; then
			sudo --user=$newuser mkdir ${HOME}/${WALLETDIR} 2>>${LOGFILE}
		else
			mkdir ${HOME}/${WALLETDIR} 2>>${LOGFILE}
		fi

		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#      Creating wallet directory: Successful" >>${LOGFILE} || echo "#      Creating wallet directory: FAILED" >>${LOGFILE}
	fi

	if [ $osver = "xenial" ]; then
		#download Ubuntu 16.04 wallet
		filename="${U16WALLETLINK##*/}"
		filepath=$HOME'/'$filename
		echo -en " Loading wallet ${filename} \r"
		[ $newusermn -eq 1 ] && sudo --user=$newuser wget ${U16WALLETLINK} &>>${LOGFILE} || cd ~ && wget ${U16WALLETLINK} &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1

	fi

	echo "###  Downloading wallet complete  ###" >>${LOGFILE}

	if [ -f $filepath ]; then
		folder="${filename%.*}"
		echo -ne " Extracting ${filename} \r"
		[ $newusermn -eq 1 ] && sudo --user=$newuser unzip -o ${filename} -d ${HOME}/${WALLETDIR}/ &>>${LOGFILE} || unzip -o ${filename} -d ${HOME}/${WALLETDIR}/ &>>${LOGFILE} 
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1

		echo -ne " Updating permissions in ${WALLETDIR} \r"
		[ $newusermn -eq 1 ] && sudo --user=$newuser chmod +x ${WALLETDIR}/* &>>${LOGFILE} || chmod +x ${WALLETDIR}/* &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1

		echo -ne " Removing archive ${filename} \r"
		[ $newusermn -eq 1 ] && sudo rm -f ${filename} &>>${LOGFILE} || rm -f $filename &>>${LOGFILE}
		#rm $filename
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1

	fi

	if [ $loadonboot -eq 1 ]; then
		if [ -f $HOME/$WALLETDIR/$DAEMONFILE ]; then
			start_on_reboot
		else
			echo "#    Daemon file doesn't exist, skipping crontab update." >>${LOGFILE}

		fi
	fi
	echo
}

function configure_masternode() {
	#mn configuration    [0.30]
	echo "CONFIGURING MASTERNODE"
	echo >>${LOGFILE}
	echo "###    Masternode configuration started    ###" >>${LOGFILE}
	ec=0
	datadir=$HOME'/'$DATADIRNAME
	coinconf=$datadir'/'$CONFFILENAME
	walletpath=$HOME'/'$WALLETDIR

	if [ ! -d "$datadir" ]; then
		echo "#      Creating datadirectory" >>${LOGFILE}
		echo -ne " Creating datadirectory \r"
		if [ $newusermn -eq 1 ]; then
			sudo --user=$newuser mkdir ${datadir} 2>>${LOGFILE}
		else
			mkdir $datadir 2>>${LOGFILE}
		fi

		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#      Creating datadirectory: Successful" >>${LOGFILE} || echo "#      Creating datadirectory: FAILED" >>${LOGFILE}
	fi

	if [ -f $coinconf ]; then
		bakfile=$coinconf".backup_$(date +%y-%m-%d-%s)"
		echo -ne " Creating ${CONFFILENAME} backup \r"
		if [ $newusermn -eq 1 ]; then
			sudo --user=$newuser cp ${coinconf} ${bakfile} 2>>${LOGFILE}
		else
			cp $coinconf $bakfile &>>${LOGFILE}
		fi
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#      Backup of ${CONFFILENAME}: Successful" >>${LOGFILE} || echo "#      Backup of ${CONFFILENAME}: FAILED" >>${LOGFILE}
	fi
	if [ -f $datadir"/wallet.dat" ]; then
		bakfile=$datadir"/wallet.dat.backup_$(date +%y-%m-%d-%s)"
		echo -ne " Creating wallet.dat backup \r"
		if [ $newusermn -eq 1 ]; then
			sudo --user=$newuser cp ${datadir}/wallet.dat ${bakfile} 2>>${LOGFILE}
		else
			cp $coinconf $bakfile &>>${LOGFILE}
		fi
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#      Backup of wallet.dat: Successful" >>${LOGFILE} || echo "#      Backup of wallet.dat: FAILED" >>${LOGFILE}

	fi

	#create conf file
	echo -ne " Clearing ${CONFFILENAME} \r"
	echo "#      Creating ${CONFFILENAME}      " >>${LOGFILE}
	ec=0
	if [ $newusermn -eq 1 ]; then
		sudo --user=$newuser echo >${coinconf} 2>>${LOGFILE}
	else
		echo >${coinconf} 2>>${LOGFILE}
	fi

	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	[ $ec -eq 0 ] && echo "#      Clearing of ${coinconf}: Successful" >>${LOGFILE} || echo "#       Clearing of ${coinconf}: FAILED" >>${LOGFILE}

	echo -ne " Configuring ${CONFFILENAME} \r"
	echo "# RPC configuration part " >>${coinconf}
	echo "server=1" >>${coinconf}
	echo "rpcuser=${rpcuser}" >>${coinconf}
	echo "rpcpassword=${rpcpassword}" >>${coinconf}
	echo "rpcconnect=127.0.0.1" >>${coinconf}
	echo "rpcport=${RPCPORT}" >>${coinconf}
	echo "rpcthreads=8" >>${coinconf}
	echo "rpcallowip=127.0.0.1" >>${coinconf}
	echo >>${coinconf}
	echo "# P2P configuration part" >>${coinconf}
	echo "daemon=1" >>${coinconf}
	echo "listen=1" >>${coinconf}
	echo "externalip=${vpsip}" >>${coinconf}
	echo "port=${P2PPORT}" >>${coinconf}
	echo "maxconnections=256" >>${coinconf}
	echo >>${coinconf}
	echo "# Masternode configuration part" >>${coinconf}
	echo "masternode=1" >>${coinconf}
	#echo "masternodeaddr=${vpsip}:${P2PPORT}" >>${coinconf}
	echo "masternodeprivkey=${mnprivkey}" >>${coinconf}
	#echo "# Addnode section" >>${coinconf}
	#echo "addnode=aaa.bbb.ccc.ddd:port" >>${coinconf}


	[ $? -eq 0 ] && ec=0 || ec=1
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	[ $ec -eq 0 ] && echo "#      Configuring of ${coinconf}: Successful" >>${LOGFILE} || echo "#       Configuring of ${coinconf}: FAILED" >>${LOGFILE}
	chown $USER:$USER ${coinconf} >>${LOGFILE} 2>&1
	#check the daemon not running
	if [ -f ${datadir}/${DAEMONFILE}.pid ]; then
		echo -en " Force stopping daemon \r"
		sudo pkill -9 -f ${DAEMONFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#      Force stopping daemon: Successful" >>${LOGFILE} || echo "#       Force stopping daemon: FAILED" >>${LOGFILE}
	fi

	#starting daemon
	echo "#      Starting daemon      " >>${LOGFILE}
	echo -en " Starting daemon  \r"
	echo "#      Executing "${walletpath}/${DAEMONFILE}" -daemon" >>${LOGFILE}
	if [ $newusermn -eq 1 ]; then
		sudo --user=$newuser ${walletpath}/${DAEMONFILE} -daemon >>${LOGFILE} 2>&1
	else
		${walletpath}/${DAEMONFILE} -daemon >>${LOGFILE} 2>&1
	fi

	[ $? -eq 0 ] && ec=0 || ec=1
	sleep 5
	#echo -en " Starting daemon  \r"
	[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
	[ $ec -eq 0 ] && echo "#      Daemon start: Successful" >>${LOGFILE} || echo "#       Daemon start: FAILED" >>${LOGFILE}

	echo -en " Waiting a bit...  \r"
	sleep 5
	echo -en " Checking pid file \r"
	if [ -f ${datadir}/${DAEMONFILE}.pid ]; then
		pid=$(more ${datadir}/${DAEMONFILE}.pid)
		[ $? -eq 0 ] && ec=0 || ec=1
		echo -en " Checking pid file: pid=${pid} \r"
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#      Process pid (${pid}): Successful" >>${LOGFILE} || echo "#       Reading pid file: FAILED" >>${LOGFILE}
	else
		pid=0
		echo -en " ${RED}ERROR: Failed to start daemon, further steps aborted ${NC}\n"
		echo
		exit
	fi

	if [ $pid -gt 0 ]; then
		echo -en " Synchronizing with blockchain \r"
		echo "#      Synchronizing with blockchain  " >>${LOGFILE}
		sleep 5
		synced="false"
		while
			! [ "$synced" = "true" ]; do
			synced=$(${walletpath}/${CLIFILE} mnsync status | grep IsBlockchainSynced | grep -oE '(true|false)' 2>>${LOGFILE})
			currentblk=$(${walletpath}/${CLIFILE} getinfo | grep blocks | grep -oE '[0-9]*' 2>>${LOGFILE})
			echo -en " Synchronizing with blockchain: block ${currentblk} \r"
			echo "#      Loaded blocks: ${currentblk}" >>${LOGFILE}
			sleep 2
		done
		echo -en " Synchronizing with blockchain: block ${currentblk} \r"
		[ "$synced" = "true" ] && echo -en $STATUS0 || echo -en $STATUS1
		echo "#      Synchronizing with blockchain ...    [ Done ]" >>${LOGFILE}

		#local p2p port check
		echo "#        Checking p2p port reachability to tcp/"$P2PPORT &>>${LOGFILE}
		echo -en " Checking local p2p port reachability to tcp/${P2PPORT} \r"
		portstatus=$((echo > /dev/tcp/$vpsip/$P2PPORT) >/dev/null 2>&1     && echo "Successful" || echo "FAILED")
		[ "$portstatus" = "Successful" ] && echo -en $STATUS0 || echo -en $STATUS1
		[ "$portstatus" = "Successful" ] && echo "#      Local port check: Successful" >>${LOGFILE} || echo "#       Local port check: FAILED" >>${LOGFILE}
		#remote p2p port check
		echo -en " Checking remote p2p port reachability to tcp/${P2PPORT} \r"
		remote_portcheck
		[ "$remportcheck" = "Successful" ] && echo -en $STATUS0 || echo -en $STATUS1
		[ "$remportcheck" = "Successful" ] && echo "#      Remote port check: Successful" >>${LOGFILE} || echo "#       Remote port check: FAILED" >>${LOGFILE}
		#check mnsync status
		echo -en " Synchronizing masternode \r"
		echo "#      Synchronizing masternode ...    " >>${LOGFILE}
		synced="false"
		while
			! [ "$synced" = "true" ]; do
			synced=$(${walletpath}/${CLIFILE} mnsync status | grep IsSynced | grep -oE '(true|false)' 2>>${LOGFILE})
			echo -ne " Waiting for masternode synchronization: IsSynced = ${synced} \r"
			sleep 5
		done
		echo -ne " Waiting for masternode synchronization: IsSynced = ${synced} \r"
		[ "$synced" = "true" ] && echo -en $STATUS0 || echo -en $STATUS1
		[ "$synced" = "true" ] && echo "#      Masternode synchronization: Successful" >>${LOGFILE} || echo "#       Masternode synchronization: FAILED" >>${LOGFILE}
		echo "###  Masternode configuration complete  ###" >>${LOGFILE}
		echo "MASTERNODE CONFIGURATION FINISHED"
		sleep 5
		#check masternode status
		mnstatus=$(${walletpath}/${CLIFILE} masternode status | grep 'status' | grep -oE ': *".*"' | grep -oE '".*"' | grep -oE '[a-zA-Z0-9 :,.!]*')
		currentblk=$(${walletpath}/${CLIFILE} getinfo | grep blocks | grep -oE '[0-9]*')
		echo
		echo "===================================================================="
		echo "                  MASTERNODE CONFIGURATION FINISHED                 "
		echo "===================================================================="
		echo
		echo -en "Node IP endpoint: ${PURPLE}"$vpsip:$P2PPORT"${NC}\n"
		echo -en "Masternode private key: ${PURPLE}"$mnprivkey"${NC}\n"
		echo -en "Collateral tx hash: ${PURPLE}"$txhash"${NC}\n"
		echo -en "Collateral tx output: ${PURPLE}"$txoutput"${NC}\n"
		echo
		echo -en "Local p2p port connection test: "
		[ "$portstatus" = "Successful" ] && echo -en "${GREEN}${portstatus}${NC}\n" || echo -en "${RED}${portstatus}${NC}\n"
		echo -en "Remote p2p port connection test: "
		[ "$remportcheck" = "Successful" ] && echo -en "${GREEN}${remportcheck}${NC}\n" || echo -en "${RED}${remportcheck}${NC}\n"
		echo
		echo -en "Current daemon block: ${PURPLE}"$currentblk"${NC}\n"
		echo -en "VPS MN status: "
		[ "$mnstatus" = "Masternode successfully started" ] && echo -en "${GREEN}${mnstatus}${NC}\n" || echo -en "${RED}${mnstatus}${NC}\n"
		echo
		echo -en "Wallet installation path: ${PURPLE}"$walletpath"${NC}\n"
		echo -en "Data directory path: ${PURPLE}"$datadir"${NC}\n"
		echo
		echo "===================================================================="
		echo
		if [ "$portstatus" = "FAILED" ] || [ "$remportcheck" = "FAILED" ]; then
			echo -en "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			echo
			echo " ATTENTION: P2P port connection test failed!"
			echo
			echo " Please check firewall settings to insure tcp port ${P2PPORT} is"
			echo " reachable from Internet."
			echo
			echo -en "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}\n"
			echo
			echo
		fi
		read -n1 -p " Press any key to continue..." ll
		echo
		#show instruction to start masternode in local wallet
		echo "  PLEASE FOLLOW INSTRUCTIONS BELOW TO START YOUR MASTERNODE  "
		echo
		sleep 5
		echo "1. Open your local wallet."
		echo
		echo -en "2. Navigate to ${PURPLE}Menu -> Tools -> Open Masternode Configuration File${NC}\n"
		echo "    open file with text editor, e.g. Notepad"
		echo
		echo "3. Add new line at the bottom (replace 'mnalias' with desired name)"
		echo
		echo -en "${PURPLE}mnalias "$vpsip:$P2PPORT" "$mnprivkey" "$txhash" "$txoutput"${NC}\n"
		echo
		echo "   Save file"
		echo
		echo -en "4. Restart your local wallet and ${UL}wait for full synchronization${NC}\n"
		echo -en "   Insure that your collateral tx has at least ${PURPLE}${UL}15 confirmations${NC}\n"
		echo
		echo -en "5. Navigate to ${PURPLE}Menu -> Tools -> Debug Console${NC}\n"
		echo
		echo "6. Start masternode using command (replace 'mnalias' with actual name):"
		echo
		echo -en "    ${PURPLE}masternode start-alias mnalias ${NC}\n"
		echo
		echo "======================================================================"
		echo
		read -n1 -p " After successful masternode start in local wallet press any key..." ll
		echo
		mnstatus=$(${walletpath}/${CLIFILE} masternode status | grep 'status' | grep -oE ': *".*"' | grep -oE '".*"' | grep -oE '[a-zA-Z0-9 :,.!]*' 2>>${LOGFILE})
		mnstate=$(${walletpath}/${CLIFILE} masternode list full $txhash | grep -oE '(PRE_ENABLED|ENABLED|EXPIRED|WATCHDOG_EXPIRED|NEW_START_REQUIRED|UPDATE_REQUIRED|POSE_BAN|OUTPOINT_SPENT|DISABLED)')
		#mnstate=$(${walletpath}/${CLIFILE} listmasternodes $txhash | grep -oE '(PRE_ENABLED|ENABLED|EXPIRED|WATCHDOG_EXPIRED|NEW_START_REQUIRED|UPDATE_REQUIRED|POSE_BAN|OUTPOINT_SPENT)' 2>>${LOGFILE})
		logstate=$mnstate
		if [ "$mnstate" = "" ]; then
			logstate="NOT IN LIST"
			mnstate="${RED}NOT IN LIST${NC}"
		elif [ "$mnstate" = "PRE_ENABLED" ] || [ "$mnstate" = "ENABLED" ]; then
			mnstate="${GREEN}${mnstate}${NC}"
		else
			mnstate="${RED}${mnstate}${NC}"
		fi
		echo "####   POST START CHECKS ####" >>${LOGFILE}
		echo "#   Post-start Mastrnode status: "$mnstatus >>${LOGFILE}
		echo "#   Masternode state: "$logstate >>${LOGFILE}
		echo -en " Post-start Masternode status: "
		[ "$mnstatus" = "Masternode successfully started" ] && echo -en "${GREEN}${mnstatus}${NC}\n" || echo -en "${RED}${mnstatus}${NC}\n"
		echo -en " Masternode list state: "$mnstate"\n"
		echo
		echo " Please use command below to check masternode status from command line:"
		echo
		echo -en "${PURPLE}  ${walletpath}/${CLIFILE} masternode status${NC}\n"
		echo
		if [ $newusermn -eq 1 ]; then
			echo -en "  WARNING: Installation was done under ${PURPLE}${newuser}${NC} account\n"
			echo -en "           To run commands correcly, relogin as ${PURPLE}${newuser}${NC} or switch user with command below: \n"
			echo
			echo -en "               ${PURPLE}cd ${HOME} && su ${newuser}${NC}\n"
			echo
		fi
		echo
	else
		echo -en "${RED} DAEMON FAILED TO START, MASTERNODE SETUP ABORTED ${NC}\n"
		echo "#      Daemon failed to start, masternode setup aborted." >>${LOGFILE}
	fi
}
function remote_portcheck() {
	result=$(curl -sH 'Accept: application/json' https://check-host.net/check-tcp\?host=$vpsip:$P2PPORT\&max_nodes=1)
	echo "#    Remote port check result:" >>${LOGFILE}
	echo $result >>$LOGFILE
	rid=$(echo $result | cut -d',' -f 8)
	link=$(echo ${rid//\\/} | cut -d'"' -f 4)
	sleep 2
	result=$(curl -s $link | grep check_displayer.display | grep -oE 'time|error')
	if [ "$result" = "time" ]; then remportcheck="Successful"; else remportcheck="FAILED"; fi
	if [ "$remportcheck" = "FAILED" ]; then
		# let's check once more
		result=$(curl -sH 'Accept: application/json' https://check-host.net/check-tcp\?host=$vpsip:$P2PPORT\&max_nodes=1)
		echo "#    Remote port check result:" >>${LOGFILE}
		echo $result >>$LOGFILE
		rid=$(echo $result | cut -d',' -f 8)
		link=$(echo ${rid//\\/} | cut -d'"' -f 4)
		sleep 2
		result=$(curl -s $link | grep check_displayer.display | grep -oE 'time|error')
		if [ "$result" = "time" ]; then remportcheck="Successful"; else remportcheck="FAILED"; fi
	fi
}
function create_user() {
	#create non-root user [0.20]
	echo "CREATING NEW USER"
	if [ $newsudouser -eq 1 ]; then
		echo -en " Creating new sudo user (${newuser})\r"
		echo "#    Creating new sudo user (${newuser})" >>${LOGFILE}
		echo "$    sudo useradd -d /home/$newuser -m -G sudo -s /bin/bash -p $ePass $newuser" >>${LOGFILE}
		sudo useradd -d /home/$newuser -m -G sudo -s /bin/bash -p $ePass $newuser &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    Creating new sudo user (${newuser}) successful" >>${LOGFILE} || echo "#    Creating new sudo user (${newuser}) FAILED" >>${LOGFILE}
		if [ $sudowopass -eq 1 ]; then
			echo -en " Assigning sudo permissions without password \r"
			echo "#    Assigning sudo permissions without password" >>${LOGFILE}
			sudo echo "${newuser} ALL=(ALL:ALL) NOPASSWD: ALL" >/etc/sudoers.d/$newuser
			sudo chmod 440 /etc/sudoers.d/$newuser &>>${LOGFILE}
			[ $? -eq 0 ] && ec=0 || ec=1
			[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
			[ $ec -eq 0 ] && echo "#    Assigning sudo permissions without password successful" >>${LOGFILE} || echo "#    Assigning sudo permissions without password FAILED" >>${LOGFILE}
		fi
	else
		echo -en " Creating new non-sudo user (${newuser})\r"
		echo "#    Creating new non-sudo user (${newuser})" >>${LOGFILE}
		echo "$    sudo useradd -d /home/$newuser -m -s /bin/bash -p $ePass $newuser" >>${LOGFILE}
		sudo useradd -d /home/$newuser -m -s /bin/bash -p $ePass $newuser &>>${LOGFILE}
		[ $? -eq 0 ] && ec=0 || ec=1
		[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
		[ $ec -eq 0 ] && echo "#    Creating new non-sudo user (${newuser}) successful" >>${LOGFILE} || echo "#    Creating new non-sudo user (${newuser}) FAILED" >>${LOGFILE}
	fi
	if [ $newusermn -eq 1 ]; then
		echo "#    Preparing installation to user ${newuser} profile" >>${LOGFILE}
		if ! [ "$USER" = "root" ]; then
			scriptname="${SCRIPTPATH##*/}"
			echo -en " Copying script to ${newuser} home \r"
			sudo cp $SCRIPTPATH /home/$newuser
			[ $? -eq 0 ] && ec=0 || ec=1
			[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
			echo -en " Changing script owner to ${newuser} \r"
			sudo chown $newuser:$newuset /home/$newuser/*.sh
			[ $? -eq 0 ] && ec=0 || ec=1
			[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
			echo -en "\n${RED} WARNING:${NC} To continue masternode installation please switch to '"${newuser}"' account and launch the script again.\n"
			echo -en " Use below commands to run script under '"${newuser}"' account \n\n"
			echo -en "   ${PURPLE} cd /home/${newuser} && su ${newuser} \n"
			echo -en "   ./${scriptname} ${NC}\n\n"
			echo " SCRIPT TERMINATED "
			exit
		fi
		HOME=$(su -c 'cd ~ && pwd' ${newuser}) #update home directory
		USER=$newuser                          #update current user
		echo " Installation will continue using user profile: "$USER
		echo
	else
		echo
	fi
}
function start_on_reboot() {
	#update crontab to tart daemon on reboot
	if [ $loadonboot -eq 1 ]; then
		if [ $newusermn -eq 1 ]; then
			crontab -u ${newuser} -l 2>>${LOGFILE} 1>/tmp/tempcron
		else
			crontab -l 2>>${LOGFILE} 1>/tmp/tempcron
		fi
		crn=$(more /tmp/tempcron | grep $HOME'/'$WALLETDIR'/'$DAEMONFILE)
		if [ "$crn" = "" ]; then
			echo -en " Updating crontab \r"
			echo "#    Updating crontab " >>${LOGFILE}
			echo "@reboot ${HOME}/${WALLETDIR}/${DAEMONFILE} -daemon" 1>>/tmp/tempcron 2>>${LOGFILE}
			if [ $newusermn -eq 1 ]; then
				crontab -u ${newuser} /tmp/tempcron >>${LOGFILE}
			else
				crontab /tmp/tempcron >>${LOGFILE}
			fi
			[ $? -eq 0 ] && ec=0 || ec=1
			[ $ec -eq 0 ] && echo -en $STATUS0 || echo -en $STATUS1
			if [ $newusermn -eq 1 ]; then
				crontab -u ${newuser} -l >>${LOGFILE}
			else
				crontab -l >>${LOGFILE}
			fi
			[ $ec -eq 0 ] && echo "#    crontab update: Successful" >>${LOGFILE} || echo "#    crontab update: FAILED" >>${LOGFILE}
		fi
		rm /tmp/tempcron
	fi
}
function check_os_support() {
	if ! [ "${osver}" = "xenial" ]; then
			echo -en "${RED} This operating system is not supported by the script. Please contact support.${NC}\n"
			exit 1
	fi
}
function print_devsupport() {
	echo
	echo " Thank you for using this script " 
}
#switches
sysupdate=0
createswap=0
setupufw=0
setupfail2ban=0
createuser=0
setupwallet=0
setupmn=0
#defaults
swapsizegigs="2.0"
sshport=22
newsudouser=0
sudowopass=0
newusermn=0
loadonboot=0
newuser=""
ePass=""
osver=""
vpsip=""
rpcuser=""
rpcpassword=""
mnprivkey=""
txhash=""
txoutput=""
BLUE="\033[0;34m"
PURPLE="\033[0;35m"
GREEN="\033[0;32m"
RED="\033[0;31m"
NC="\033[0m"
UL="\033[4m"
portlist=()
# main procedure
SCRIPTPATH=$(readlink -f $0)
cols=$(tput cols)
if [ $cols -ge 100 ]; then cols=100; fi
mv=$(expr $cols - 11)
STATUS1="\033[${mv}C [${RED} FAILED ${NC}]\n"   #[ FAILED ]
STATUS0="\033[${mv}C [ ${GREEN} DONE ${NC} ]\n" #[  DONE  ]
cd ~
USER=$(whoami)               #current user
HOME=$(pwd)                  #home directory
LOGFILE=$HOME"/"$LOGFILENAME #create log full path
detect_osversion             #run OS version detection
echo >${LOGFILE}             #clear log file
echo "Script version: ${VERSION}" >>${LOGFILE}
echo "OS detected: ${osver}" >>${LOGFILE}
check_os_support
#clear
print_welcome                                #print welcome frame
echo "OS $(lsb_release -d) (${osver})"        #print OS version
echo "Running script using account: ${USER}" #print user account
echo "Current user home directory: ${HOME}"  #print user home dir
echo "Installation log file: "$LOGFILE       #path to log
echo
run_questionnaire #run user questionnaire
echo
echo "###############################"
echo "#     STARTING NODE SETUP     #"
echo "###############################"
echo
if [ $createswap -eq 1 ]; then create_swap; fi
if [ $sysupdate -eq 1 ]; then system_update; fi
if [ $setupfail2ban -eq 1 ]; then setup_fail2ban; fi
if [ $setupufw -ge 1 ]; then setup_ufw; fi
if [ $createuser -eq 1 ]; then create_user; fi
if [ $setupwallet -eq 1 ]; then setup_wallet; fi
if [ $setupmn -eq 1 ]; then configure_masternode; fi
echo
echo "###############################"
echo "#      NODE SETUP FINISHED    #"
echo "###############################"
echo
print_devsupport
