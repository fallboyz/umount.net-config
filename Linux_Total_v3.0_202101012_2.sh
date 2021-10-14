#!/bin/bash

#Programmer : Colin
#Date : 2021.12
#Version : 3.0
#Comment : Linux Server + Apache

LANG=C
export LANG

echo ""
echo ""
echo "Select a security diagnosis type."
echo ""
echo "----------------------------------"
echo "  1. Linux Server"
echo "  2. Apache"
echo "  3. Linux Server + Apache"
echo "----------------------------------"
echo ""

while true
do
	echo -n "Input number : "
	read Type_Num
	if [ $Type_Num -eq 1 ]
	then
		break
	elif [ $Type_Num -eq 2 ]
	then
		break
	elif [ $Type_Num -eq 3 ]
	then
		break
	else
		echo "Wrong number. Please retry."
	fi
done
	
case $Type_Num in

1)
# Linux Server

echo ""
echo ""
echo "==============================  START  ==============================" 
echo ""


IP=`ifconfig -a | grep  "inet addr" | head -1 | awk '{print $2}' | awk -F: '{print $2}'`


RESULT_FILE=./Linux@@`hostname`@@$IP.txt

echo "===============  Linux Server Security Check  ===============" > $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "Copyright (c) 2021 Coresnet Co. Ltd. All right Reserved" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



echo [U-1]root 계정 원격 접속 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-1]root 계정 원격 접속 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [1-START] >> $RESULT_FILE 2>&1
if [ `find /etc -type f -name "sshd_config" | wc -l` -eq 0 ]
	then
		echo "★ sshd_config 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [1-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-1]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SSHCONFIG=`find /etc -type f -name "sshd_config"`
		if [ `grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "#" | grep -i "no" | wc -l` -eq 0 ]
			then
				echo "★ root 계정 원격 접속이 제한되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : VULNERABLE >> $RESULT_FILE 2>&1
				
			else
				echo "★ root 계정 원격 접속이 제한됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-2]패스워드 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-2]패스워드 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [2-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "system-auth" | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-2]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "system-auth"`
		if [ `grep -i "password" $SYSAUTH | grep "requisite" | grep "lcredit" | grep "dcredit" | grep "ocredit" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 복잡성 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 패스워드 복잡성 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-2-2]패스워드 복잡성 설정u
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-2-2]패스워드 복잡성 설정u  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [2-2-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "common-auth" | wc -l` -eq 0 ]
	then
		echo "★ common-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [2-2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-2-2]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "common-auth"`
		if [ `grep -i "password" $SYSAUTH | grep "requisite" | grep "lcredit" | grep "dcredit" | grep "ocredit" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 복잡성 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 패스워드 복잡성 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2-2]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-3]계정 잠금 임계값 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-3]계정 잠금 임계값 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [3-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "system-auth" | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [3-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-3]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "system-auth"`
		if [ `grep -i "pam_tally2.so" $SYSAUTH | grep -i "deny" | wc -l` -eq 0 ]
			then
				echo "★ 계정 잠금 임계값 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTH >> $RESULT_FILE 2>&1 
				grep -i "^password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 계정 잠금 임계값 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTH >> $RESULT_FILE 2>&1 
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1			
				echo [U-3]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-3-2]계정 잠금 임계값 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-3-2]계정 잠금 임계값 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [3-2-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "common-auth" | wc -l` -eq 0 ]
	then
		echo "★ common-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [3-2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-3-2]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "common-auth"`
		if [ `grep -i "pam_tally2.so" $SYSAUTH | grep -i "deny" | wc -l` -eq 0 ]
			then
				echo "★ 계정 잠금 임계값 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTH >> $RESULT_FILE 2>&1 
				grep -i "^password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [3-2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-3-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 계정 잠금 임계값 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTH >> $RESULT_FILE 2>&1 
				echo [3-2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1			
				echo [U-3-2]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-4]패스워드 파일 보호
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-4]패스워드 파일 보호  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [4-START] >> $RESULT_FILE 2>&1
if [ `head -1 /etc/passwd | awk -F: '{print $2}' | egrep "^x" | wc -c` -eq 2 ]
	then
		echo "★ 패스워드를 /etc/passwd 파일에 저장하지 않고 별도의 파일에 저장함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		head -1 /etc/passwd >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-4]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 패스워드를 /etc/passwd 파일에 저장함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		head -1 /etc/passwd >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1	
		echo [U-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-05]root 홈, 패스 디렉터리 권한 및 패스 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-05]root 홈, 패스 디렉터리 권한 및 패스 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [05-START] >> $RESULT_FILE 2>&1
if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
	then
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [05-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-05]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [05-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-05]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-06]파일 및 디렉터리 소유자 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-06]파일 및 디렉터리 소유자 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [06-START] >> $RESULT_FILE 2>&1
ls -l /home | awk '{print $3}' | grep "^[0-9]" > tmp_06_1.txt
for i in `cat tmp_17_1.txt`; do ls -l /home | grep -w $i >> tmp_06_2.txt; done
if [ -f tmp_06_2.txt ]
	then
		echo "★ /home 디렉토리에 소유자가 존재하지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_06_2.txt >> $RESULT_FILE 2>&1
		echo [06-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-06]Result : VULNERABLE >> $RESULT_FILE 2>&1		
	else
		echo "★ /home 디렉토리에 소유자가 존재하지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [06-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-06]Result : GOOD >> $RESULT_FILE 2>&1
fi
rm -rf tmp_06_1.txt
rm -rf tmp_06_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-07]/etc/passwd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-07]/etc/passwd 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [07-START] >> $RESULT_FILE 2>&1
if [ `ls -alL /etc/passwd | grep "^...-.--.--" | awk '$3=="root"' | wc -l` -eq 1 ]
  then
	echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	ls -alL /etc/passwd >> $RESULT_FILE 2>&1
	echo [07-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-07]Result : GOOD >> $RESULT_FILE 2>&1
 else
	echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	ls -alL /etc/passwd >> $RESULT_FILE 2>&1
	echo [07-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-07]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-08]/etc/shadow 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-08]/etc/shadow 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [08-START] >> $RESULT_FILE 2>&1
if [ `ls -alL /etc/shadow | grep "^.-.-------" | awk '$3=="root"' | wc -l` -eq 1 ]
  then
	echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	ls -alL /etc/shadow >> $RESULT_FILE 2>&1
	echo [08-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-08]Result : GOOD >> $RESULT_FILE 2>&1
 else
	echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	ls -alL /etc/shadow >> $RESULT_FILE 2>&1
	echo [08-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-08]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-09]/etc/hosts 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-09]/etc/hosts 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [09-START] >> $RESULT_FILE 2>&1
if [ -f /etc/hosts ]
	then
		if [ `ls -alL /etc/hosts | grep "^....------" | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/hosts >> $RESULT_FILE 2>&1
				echo [09-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-09]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/hosts >> $RESULT_FILE 2>&1
				echo [09-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-09]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/hosts 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [09-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-09]Result : N/A >> $RESULT_FILE 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "[U-10]/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
echo "============================================================" >> $RESULT_FILE 2>&1
echo "[U-10]/etc/(x)inetd.conf 파일 소유자 및 권한 설정"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [10-START] >> $RESULT_FILE 2>&1
if [ -f /etc/xinetd.conf ]
	then
		if [ `ls -alL /etc/xinetd.conf | grep "^....------" | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/xinetd.conf >> $RESULT_FILE 2>&1
				echo [10-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-10]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/xinetd.conf >> $RESULT_FILE 2>&1
				echo [10-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-10]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		if [ -f /etc/inetd.conf ]
			then
				if [ `ls -alL /etc/inetd.conf | grep "^....------" | awk '$3=="root"' | wc -l` -eq 1 ]
					then
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ls -alL /etc/inetd.conf >> $RESULT_FILE 2>&1
						echo [10-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-10]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ls -alL /etc/inetd.conf >> $RESULT_FILE 2>&1
						echo [10-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-10]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi				
			else
				echo "★ /etc/(x)inetd.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [10-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-10]Result : GOOD >> $RESULT_FILE 2>&1 
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-11]/etc/syslog.conf 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-11]/etc/syslog.conf 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [11-START] >> $RESULT_FILE 2>&1
if [ -f /etc/syslog.conf ]
	then
		if [ `ls -alL /etc/syslog.conf | grep "^...-.--.--" | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/syslog.conf 파일의 소유자 및 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/syslog.conf >> $RESULT_FILE 2>&1
				echo [11-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-11]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/syslog.conf 파일의 소유자 및 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/syslog.conf >> $RESULT_FILE 2>&1
				echo [11-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-11]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		if [ -f /etc/rsyslog.conf ]
			then
				if [ `ls -alL /etc/rsyslog.conf | grep "^...-.--.--" | awk '$3=="root"' | wc -l` -eq 1 ]
					then
						echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ls -alL /etc/rsyslog.conf >> $RESULT_FILE 2>&1
						echo [11-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1	
						echo [U-11]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ls -alL /etc/rsyslog.conf >> $RESULT_FILE 2>&1
						echo [11-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-11]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ /etc/syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [11-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-11]Result : N/A >> $RESULT_FILE 2>&1 
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-12]/etc/services 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-12]/etc/services 파일 소유자 및 권한 설정 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [12-START] >> $RESULT_FILE 2>&1
if [ -f /etc/services ]
	then
		if [ `ls -alL /etc/services | grep "^...-.--.--" | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/services >> $RESULT_FILE 2>&1
				echo [12-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-12]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/services >> $RESULT_FILE 2>&1
				echo [12-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-12]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/services 파일이 없음" >> $RESULT_FILE 2>&1
		echo [12-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-12]Result : N/A >> $RESULT_FILE 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-13]SUID, SGID, Sticky bit 설정 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-13]SUID, SGID, Sticky bit 설정 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [13-START] >> $RESULT_FILE 2>&1
FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"
for check_file in $FILES
	do
    if [ -f $check_file ]
		then
			if [ -g $check_file -o -u $check_file ]
				then
					echo `ls -alL $check_file` >> tmp_13.txt
				else
				:
			fi
		else
		:
    fi
done
if [ -f tmp_13.txt ]
	then
		echo "★ 점검 파일 중 SUID, SGID가 설정된 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_13.txt >> $RESULT_FILE 2>&1
		echo [13-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-13]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		echo "★ 점검 파일 중 SUID, SGID가 설정된 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [13-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-13]Result : GOOD >> $RESULT_FILE 2>&1
fi
rm -rf tmp_13.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [14-START] >> $RESULT_FILE 2>&1
if [ -f /etc/profile ]
	then
		if [ `ls -alL /etc/profile | grep "^.....-..-." | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -al /etc/profile >> $RESULT_FILE 2>&1
				echo [14-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-14]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -al /etc/profile >> $RESULT_FILE 2>&1
				echo [14-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-14]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/profile 파일이 없음" >> $RESULT_FILE 2>&1
		echo [14-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-14]Result : N/A >> $RESULT_FILE 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-15]world writable 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-15]world writable 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [15-START] >> $RESULT_FILE 2>&1
find /etc -perm -2 -a -not -type l -ls > tmp_15.txt
if [ `cat tmp_15.txt | wc -l` -eq 0 ]
	then
		echo "★ /etc 디렉토리 하위에 Others에 쓰기 권한이 부여된 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [15-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-15]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ /etc 디렉토리 하위에 Others에 쓰기 권한이 부여된 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_15.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_15.txt | wc -l >> $RESULT_FILE 2>&1
		echo [15-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-15]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_15.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-16]/dev에 존재하지 않는 device 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-16]/dev에 존재하지 않는 device 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [16-START] >> $RESULT_FILE 2>&1
find /dev -type f -exec ls -l {} \; > tmp_16.txt
if [ `cat tmp_16.txt | wc -l` -eq 0 ]
	then
		echo "★ /dev 디렉토리에 major, minor nubmer를 가지지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [16-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-16]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ /dev 디렉토리에 major, minor nubmer를 가지지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_16.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_16.txt | wc -l >> $RESULT_FILE 2>&1
		echo [16-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-16]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_16.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [17-START] >> $RESULT_FILE 2>&1
ls -l /home/ | grep -v "+found" | sed -n '2,$p' | awk '{print $9}' > tmp_17_1.txt
for i in `cat tmp_17_1.txt`; do ls -al /home/$i/.rhosts; done 2>/dev/null > tmp_17_2.txt
if [ -f /etc/hosts.equiv ]; then ls -l /etc/hosts.equiv >> tmp_17_2.txt; else true; fi 
if [ `cat tmp_17_2.txt | wc -l` -eq 0 ]
	then
		echo "★ .rhosts, hosts.equiv 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [17-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-17]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_17_2.txt | wc -l` -eq `cat tmp_17_2.txt | grep "^....------" | wc -l` ]
			then
				for i in `cat tmp_17_2.txt | awk '{print $9}'`; do cat $i; done >> tmp_17_3.txt
				if [ `cat tmp_17_3.txt | grep "\+" | wc -l` -eq 0 ] 
					then
						echo "★ .rhosts, hosts.equiv 파일의 퍼미션 및 설정이 적절하게 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
						echo [17-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-17]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ .rhosts, hosts.equiv 파일의 설정이 적절하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
						echo [17-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ .rhosts, hosts.equiv 파일의 퍼미션이 적절하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
				echo [17-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_17_1.txt
rm -rf tmp_17_2.txt				
rm -rf tmp_17_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-18]접속 IP 및 포트 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-18]접속 IP 및 포트 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [18-START] >> $RESULT_FILE 2>&1
if [ -f /etc/hosts.deny ]
	then
		if [ `cat /etc/hosts.deny | grep -v "#" | grep -E "ALL:.*ALL" | wc -l` -eq 0 ]
			then
				echo "★ /etc/hosts.deny 파일에 ALL Deny 설정이 존재하지 않음" >> $RESULT_FILE 2>&1
				echo [18-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-18]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/hosts.deny 파일에 ALL Deny 설정이 적용됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/hosts.deny >> $RESULT_FILE 2>&1
				cat /etc/hosts.deny | grep -v "#" >> $RESULT_FILE 2>&1
				ls -l /etc/hosts.allow >> $RESULT_FILE 2>&1
				cat /etc/hosts.allow | grep -v "#" >> $RESULT_FILE 2>&1
				echo [18-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-18]Result : GOOD >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/hosts.deny 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [18-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-18]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-19]Finger 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-19]Finger 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [19-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "finger" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Finger 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Finger 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "finger" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-20]Anonymous FTP 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-20]Anonymous FTP 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [20-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [20-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "vsftpd.conf" -exec cat {} \; > tmp_20_1.txt
		if [ `cat tmp_20_1.txt | wc -l` -eq 0 ]
			then
				if [ `cat /etc/passwd | egrep -w "ftp|anonymous" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재하지 않음 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재함 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat /etc/passwd | egrep -w "ftp|anonymous" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				if [ `cat tmp_20_1.txt | grep "anonymous_enable" | grep -v "#" | grep -i -v "no$" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 차단됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat tmp_20_1.txt | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 허용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat tmp_20_1.txt | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi
rm -rf tmp_20_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-21]r 계열 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-21]r 계열 서비스 비활성화 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [21-START] >> $RESULT_FILE 2>&1
SERVICE_INETD="rsh|rlogin|rexec"
chkconfig --list | egrep $SERVICE_INETD > tmp_21_1.txt
if [ `cat tmp_21_1.txt | wc -l` -eq 0 ]
	then
		echo "★ r 계열 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [21-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-21]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_21_1.txt | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
			then
				echo "★ r 계열 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_21_1.txt >> $RESULT_FILE 2>&1
				echo [21-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-21]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ r 계열 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_21_1.txt | egrep "3:on|:.on|3:활성" >> $RESULT_FILE 2>&1
				echo [21-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-21]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_21_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-22]cron 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-22]cron 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [22-START] >> $RESULT_FILE 2>&1
ls -l /etc/ | egrep "cron.deny|cron.allow" > tmp_22_1.txt
if [ `cat tmp_22_1.txt | wc -l` -eq 0 ]
	then
		echo "★ cron.deny, cron.allow 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [22-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-22]Result : N/A >> $RESULT_FILE 2>&1
	else
		cat tmp_22_1.txt | grep "^.....-----" > tmp_22_2.txt
		if [ `diff tmp_22_1.txt tmp_22_2.txt | wc -l` -eq 0 ]
			then
				echo "★ cron 파일의 소유자 및 퍼미션(640)이 적절하게 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_22_1.txt >> $RESULT_FILE 2>&1
				echo [22-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-22]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ cron 파일의 소유자 및 퍼미션(640)이 적절하게 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_22_1.txt >> $RESULT_FILE 2>&1
				echo [22-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-22]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi	
rm -rf tmp_22_1.txt
rm -rf tmp_22_2.txt	
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-23]DoS 공격에 취약한 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-23]DoS 공격에 취약한 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [23-START] >> $RESULT_FILE 2>&1
SERVICE_INETD="echo|discard|daytime|chargen"
chkconfig --list | egrep $SERVICE_INETD > tmp_23_1.txt
if [ `cat tmp_23_1.txt | wc -l` -eq 0 ]
	then
		echo "★ DoS 공격에 취약한 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [23-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-23]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_23_1.txt | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
			then
				echo "★ DoS 공격에 취약한 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_23_1.txt >> $RESULT_FILE 2>&1
				echo [23-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-23]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ DoS 공격에 취약한 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_23_1.txt | egrep "3:on|:.on|3:활성" >> $RESULT_FILE 2>&1
				echo [23-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-23]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_23_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-24]NFS 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-24]NFS 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [24-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "nfsd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NFS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "nfsd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-25]NFS 접근통제 
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-25]NFS 접근통제   >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [25-START] >> $RESULT_FILE 2>&1

if [ `ps -ef | grep -i "nfsd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [25-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ -f /etc/exports ]
			then
				if [ `cat /etc/exports | grep -i "everyone" | grep -v "^ *#" | wc -l` -eq 0 ]
					then
						echo "★ NFS 서비스가 실행중이나 everyone 공유가 존재하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep -i "nfsd" | grep -v "grep" >> $RESULT_FILE 2>&1
						cat /etc/exports >> $RESULT_FILE 2>&1 
						echo [25-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ NFS 서비스가 실행중이고 everyone 공유가 존재함" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep -i "nfsd" | grep -v "grep" >> $RESULT_FILE 2>&1
						cat /etc/exports >> $RESULT_FILE 2>&1 
						echo [25-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-25]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ NFS 서비스가 실행중이나 /etc/exports 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep -i "nfsd" | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [25-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-25]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-26]automountd 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-26]automountd 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [26-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "automountd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ automountd 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ automountd 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "automountd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-27]RPC 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-27]RPC 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [27-START] >> $RESULT_FILE 2>&1
SERVICE_RPC="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"
if [ `chkconfig --list | egrep "$SERVICE_RPC" | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
	then
		echo "★ RPC 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [27-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-27]Result : GOOD >> $RESULT_FILE 2>&1		
	else
		echo "★ RPC 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		chkconfig --list | egrep "$SERVICE_RPC" >> $RESULT_FILE 2>&1
		echo [27-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-27]Result : VULNERABLE >> $RESULT_FILE 2>&1	
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-28]NIS, NIS+ 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-28]NIS, NIS+ 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [28-START] >> $RESULT_FILE 2>&1
SERVICE_NIS="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"
if [ `ps -ef | egrep $SERVICE_NIS | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NIS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NIS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep $SERVICE_NIS | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-29]tftp, talk 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-29]tftp, talk 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [29-START] >> $RESULT_FILE 2>&1
if [ `chkconfig --list | egrep "tftp|talk" | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
	then
		echo "★ tftp, talk 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [29-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-29]Result : GOOD >> $RESULT_FILE 2>&1		
	else
		echo "★ tftp, talk 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		chkconfig --list | egrep "tftp|talk" >> $RESULT_FILE 2>&1
		echo [29-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-29]Result : VULNERABLE >> $RESULT_FILE 2>&1	
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-30]Sendmail 버전 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-30]Sendmail 버전 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [30-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [30-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [30-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-30]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_30_1.txt \;			
				if [ `cat tmp_30_1.txt | grep -v '^ *#' | grep DZ | egrep "8.15" | wc -l` -eq 0 ]
					then
						echo "★ 취약한 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat tmp_30_1.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ 취약하지 않은 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat tmp_30_1.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_30_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-31]스팸 메일 릴레이 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-31]스팸 메일 릴레이 제한 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [31-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [31-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-31]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [31-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-31]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_31_1.txt \;
				if [ `cat tmp_31_1.txt | grep -v "^ *#" | grep "R$\*" | grep -i "Relaying denied" | wc -l ` -gt 0 ]
					then
						echo "★ 스팸 메일 릴레이 제한 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat tmp_31_1.txt | grep -v "^ *#" | grep "R$\*" | grep -i "Relaying denied" >> $RESULT_FILE 2>&1
						echo [31-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-31]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 스팸 메일 릴레이 제한 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat tmp_31_1.txt | grep "R$\*" | grep -i "Relaying denied" >> $RESULT_FILE 2>&1
						echo [31-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-31]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_31_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-32]일반사용자의 Sendmail 실행 방지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-32]일반사용자의 Sendmail 실행 방지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [32-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [32-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-32]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [32-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-32]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_32_1.txt \;
				if [ `cat tmp_32_1.txt | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "#" | wc -l` -gt 0 ]
					then
						echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat tmp_32_1.txt | grep -i "O PrivacyOptions" | grep -i "restrictqrun" >> $RESULT_FILE 2>&1
						echo [32-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-32]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat tmp_32_1.txt | grep -i "O PrivacyOptions" >> $RESULT_FILE 2>&1
						echo [32-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-32]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_32_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-33]DNS 보안 버전 패치
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-33]DNS 보안 버전 패치 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [33-START] >> $RESULT_FILE 2>&1
if [ `netstat -anp | awk '{print $4}' | grep ":53$" | wc -l` -eq 0 ]
	then
		echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [33-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-33]Result : GOOD >> $RESULT_FILE 2>&1
	else
		named -v > /dev/null
		if [ $? -eq 0 ]
			then
				echo "★ DNS 서비스가 실행중이며 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				named -v >> $RESULT_FILE 2>&1
				echo [33-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ -f /usr/sbin/named ]
					then
						echo "★ DNS 서비스가 실행중임 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						/usr/sbin/named -v >> $RESULT_FILE 2>&1
						echo [33-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
					else
						if [ -f /usr/sbin/named9 ]
							then
								echo "★ DNS 서비스가 실행중임 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
								echo "[현황]" >> $RESULT_FILE 2>&1
								/usr/sbin/named9 -v >> $RESULT_FILE 2>&1
								echo [33-END] >> $RESULT_FILE 2>&1
								echo >> $RESULT_FILE 2>&1
								echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
							else
								echo "★ DNS 서비스가 실행중이나 실행 데몬을 찾을 수 없음" >> $RESULT_FILE 2>&1
								echo [33-END] >> $RESULT_FILE 2>&1
								echo >> $RESULT_FILE 2>&1
								echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
						fi
				fi
		fi
fi		
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-34]DNS ZoneTransfer 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-34]DNS ZoneTransfer 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [34-START] >> $RESULT_FILE 2>&1
if [ `netstat -anp | awk '{print $4}' | grep ":53$" | wc -l` -eq 0 ]
	then
		echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [34-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-34]Result : GOOD >> $RESULT_FILE 2>&1
	else
		cat /etc/named.conf /etc/named.rfc1912.zones /etc/named.boot > tmp_34_1.txt 2> /dev/null
		if [ `cat tmp_34_1.txt | wc -l` -eq 0 ]
			then
				echo "★ DNS 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1
				echo [34-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-34]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ `cat tmp_34_1.txt | grep "allow-transfer" | grep -v "#" | wc -l` -eq 0 ]
					then
						echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1						
						echo [34-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-34]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1
						cat tmp_34_1.txt | grep "allow-transfer" | grep -v "#" >> $RESULT_FILE 2>&1
						echo [34-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-34]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_34_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-42]최신 보안패치 및 벤더 권고사항 적용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-42]최신 보안패치 및 벤더 권고사항 적용  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
# echo [42-START] >> $RESULT_FILE 2>&1
# echo "★ 인터뷰 점검 항목" >> $RESULT_FILE 2>&1
# echo [42-END] >> $RESULT_FILE 2>&1
# echo >> $RESULT_FILE 2>&1
# echo [U-42]Result : MANUAL >> $RESULT_FILE 2>&1
echo [42-START] >> $RESULT_FILE 2>&1
echo "★ 아래 현황을 기반으로 수동분석" >> $RESULT_FILE 2>&1
echo "[현황]" >> $RESULT_FILE 2>&1
echo "1. OpenSSL Version" >> $RESULT_FILE 2>&1
openssl version >> $RESULT_FILE 2>&1
echo "2. Bash Shell Version" >> $RESULT_FILE 2>&1
bash --version | grep "bash" >> $RESULT_FILE 2>&1
rpm -qa | grep bash >> $RESULT_FILE 2>&1
echo "2.1 Bash 취약점 테스트(벤더사 제공)" >> $RESULT_FILE 2>&1
env x='() { :;}; echo vulnerable' bash -c "echo this is a test" >> $RESULT_FILE 2>&1
echo [42-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-42]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-43]로그의 정기적 검토 및 보고
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-43]로그의 정기적 검토 및 보고  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [43-START] >> $RESULT_FILE 2>&1
echo "★ 인터뷰 점검 항목" >> $RESULT_FILE 2>&1
echo [43-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-43]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-44]root 이외의 UID가 '0' 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-44]root 이외의 UID가 '0' 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [44-START] >> $RESULT_FILE 2>&1
if [ `awk -F: '$3==0 {print $0}' /etc/passwd | grep -v 'root' | wc -l` -eq 0 ]
	then
		echo "★ root 이외의 UID가 '0'인 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-5]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ root 이외의 UID가 '0'인 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-44]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-45]root 계정 su 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-45]root 계정 su 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [45-START] >> $RESULT_FILE 2>&1
if [ -f /etc/pam.d/su ]
	then
		if [ `grep "wheel.so" /etc/pam.d/su | grep -v "trust" | grep -v "#" | grep "use_uid" | wc -l` -eq 0 ]
			then
				echo "★ su 명령 사용이 특정 그룹으로 제한되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep "wheel.so" /etc/pam.d/su >> $RESULT_FILE 2>&1
				echo [45-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-45]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ su 명령 사용이 특정 그룹으로 제한되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep "wheel.so" /etc/pam.d/su >> $RESULT_FILE 2>&1
				echo [45-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-45]Result : GOOD >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/pam.d/su 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [45-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-45]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-46]패스워드 최소 길이 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-46]패스워드 최소 길이 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [46-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "system-auth" | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [46-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-46]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "system-auth"`
		if [ `grep -i "password" /etc/pam.d/system-auth | grep "minlen" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최소 길이 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [46-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-46]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep -i "password" /etc/pam.d/system-auth | awk -F "minlen=" '{print $2}' | awk '{print $1}'` -gt 46 ]
					then
						echo "★ 패스워드 최소 길이 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
						echo [46-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-46]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최소 길이 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
						echo [46-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-46]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-47]패스워드 최대 사용 기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-47]패스워드 최대 사용 기간 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [47-START] >> $RESULT_FILE 2>&1
touch tmp_47_3.txt
cat /etc/passwd | egrep -v 'false|nologin|null|halt|sync|shutdown' > tmp_47_1.txt
cat tmp_47_1.txt | awk -F: '{print $1}' > tmp_47_2.txt
for i in `cat tmp_47_2.txt`; do 
echo user: "              $i" >> tmp_47_3.txt
chage -l $i | grep 'Last' >> tmp_47_3.txt; done
if [ -f /etc/login.defs ]
	then
		if [ `grep "PASS_MAX_DAYS" /etc/login.defs | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최대 사용 기간 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [47-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep "PASS_MAX_DAYS" /etc/login.defs | grep -v "#" | awk '{print $2}'` -gt 90 ]
					then
						echo "★ 패스워드 최대 사용 기간 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MAX_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo "1. 계정별 패스워드 최근 변경일" >> $RESULT_FILE 2>&1
						cat tmp_47_3.txt >> $RESULT_FILE 2>&1
						echo [47-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최대 사용 기간 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MAX_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo "1. 계정별 패스워드 최근 변경일" >> $RESULT_FILE 2>&1
						cat tmp_47_3.txt >> $RESULT_FILE 2>&1
						echo [47-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1					
						echo [U-47]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
	else
		echo "★ /etc/login.defs 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm tmp_47_1.txt
rm tmp_47_2.txt
rm tmp_47_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-48]패스워드 최소 사용기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-48]패스워드 최소 사용기간 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [48-START] >> $RESULT_FILE 2>&1
if [ -f /etc/login.defs ]
	then
		if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [48-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-48]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | awk '{print $2}'` -eq 1 ]
					then
						echo "★ 패스워드 최소 사용 기간 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1				
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [48-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1	
						echo [U-48]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [48-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-48]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
	else
		echo "★ /etc/login.defs 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [48-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-48]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-49]불필요한 계정 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-49]불필요한 계정 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [49-START] >> $RESULT_FILE 2>&1
touch tmp_49_3.txt
cat /etc/passwd | egrep -v 'false|nologin|null|halt|sync|shutdown|rpm|new' > tmp_49_1.txt
cat tmp_49_1.txt | awk -F: '{print $1}' > tmp_49_2.txt
for i in `cat tmp_49_2.txt`; do 
lastlog -u $i | grep $i >> tmp_49_3.txt; done
if [ `awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | grep -v "nfsnobody" | wc -l` -eq 0 ]
	then
		echo "★ UID 500 이상 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat tmp_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ UID 500 이상 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | grep -v "nfsnobody" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat tmp_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm tmp_49_1.txt
rm tmp_49_2.txt
rm tmp_49_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-50]관리자 그룹에 최소한의 계정 포함
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-50]관리자 그룹에 최소한의 계정 포함  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [50-START] >> $RESULT_FILE 2>&1
grep "^root" /etc/group | awk -F ":" '{print $4}' | sed s/,/\\n/g | grep -v "^root$" | wc -w > tmp_50.txt
if [ `cat tmp_50.txt` -eq 0 ]
	then
		echo "★ 관리자 그룹에 root 이외의 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 관리자 그룹에 root 이외의 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf tmp_50.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-51]계정이 존재하지 않는 GID 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-51]계정이 존재하지 않는 GID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [51-START] >> $RESULT_FILE 2>&1
awk -F : '$4 == null {print $0}' /etc/group | awk -F : '$3 >= 500 {print $0}' > tmp_group.txt
awk -F : '{print $4}' /etc/passwd > tmp_passwd.txt
for TGID in `cat tmp_passwd.txt`
	do
		grep -v ":$TGID:" tmp_group.txt > tmp.txt
		cat tmp.txt > tmp_group.txt
done
if [ `cat tmp_group.txt | wc -w` -eq 0 ]
	then
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		cat tmp_group.txt >> $RESULT_FILE 2>&1 
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_group.txt
rm -rf tmp_passwd.txt
rm -rf tmp.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-52]동일한 UID 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-52]동일한 UID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [52-START] >> $RESULT_FILE 2>&1
awk -F : '{print $3}' /etc/passwd > tmp_passwd.txt
if [ `cat tmp_passwd.txt | sort | uniq -d | wc -l` -eq 0 ]
	then
		echo "★ 중복된 UID가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [52-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-52]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 중복된 UID가 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		DUID=`cat tmp_passwd.txt | sort | uniq -d`
		grep "x:$DUID:" /etc/passwd >> $RESULT_FILE 2>&1
		echo [52-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-52]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_passwd.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-53]사용자 shell 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-53]사용자 shell 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [53-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  awk -F: '{print $7}'| egrep -v 'false|nologin|null|halt|sync|shutdown' | wc -l` -eq 0 ]
	then
		echo "★ 점검 대상 시스템 계정에 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 점검 대상 시스템 계정에 쉘이 부여됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-54]Session Timeout 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-54]Session Timeout 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [54-START] >> $RESULT_FILE 2>&1
if [ `echo $TMOUT | wc -w` -eq 0 ]
	then
		echo "★ 세션 타임아웃이 설정되지 않음" >> $RESULT_FILE 2>&1
		echo [54-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-54]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		if [ `echo $TMOUT` -gt 600 ]
			then
				echo "★ 세션 타임아웃이 설정되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				echo "TMOUT : `echo $TMOUT`" >> $RESULT_FILE 2>&1
				echo [54-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-54]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 세션 타임아웃이 정책에 맞게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				echo "TMOUT : `echo $TMOUT`" >> $RESULT_FILE 2>&1
				echo [54-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-54]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-55]hosts.lpd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-55]hosts.lpd 파일 소유자 및 권한 설정 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [55-START] >> $RESULT_FILE 2>&1
if [ -f /etc/hosts.lpd ]
	then
		if [ `ls -l /etc/hosts.lpd | grep "^........-." | awk '$3=="root"' | wc -l` -eq 0 ]
			then
				echo "★ /etc/hosts.lpd 파일의 소유자 및 퍼미션(o-w)이 적절하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/hosts.lpd >> $RESULT_FILE 2>&1
				echo [55-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-55]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/hosts.lpd 파일의 소유자 및 퍼미션(o-w)이 적절하게 설정되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/hosts.lpd >> $RESULT_FILE 2>&1
				echo [55-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-55]Result : GOOD >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/hosts.lpd 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [55-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-55]Result : GOOD >> $RESULT_FILE 2>&1
fi	
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-56]NIS 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-56]NIS 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [56-START] >> $RESULT_FILE 2>&1
NISSERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
if [ `ps -ef | egrep $NISSERVICE | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NIS, NIS+ 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [56-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-56]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NIS, NIS+ 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep $SERVICE | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [56-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-56]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-57]UMASK 설정 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-57]UMASK 설정 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [57-START] >> $RESULT_FILE 2>&1
if [ `umask` -eq 0022 ]
	then
		echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1		
		echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
		echo [57-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `umask` -eq 0027 ]
			then
				echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [57-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ UMASK 값이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [57-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-57]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-58]홈디렉토리 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-58]홈디렉토리 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [58-START] >> $RESULT_FILE 2>&1
ls -l /home/ | grep -v "+found" | sed -n '2,$p' > tmp_58_1.txt
cat tmp_58_1.txt | grep -v "^........w." > tmp_58_2.txt
if [ `cat tmp_58_1.txt | wc -l` -eq 0 ]
	then
		echo "★ 사용자 홈디렉토리가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [58-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-58]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `diff tmp_58_1.txt tmp_58_2.txt | wc -l` -eq 0 ]
			then
				echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_58_1.txt >> $RESULT_FILE 2>&1
				echo [58-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-58]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_58_1.txt | grep "^........w." >> $RESULT_FILE 2>&1
				echo [58-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-58]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_58_1.txt
rm -rf tmp_58_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-59]홈디렉토리로 지정한 디렉토리의 존재 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-59]홈디렉토리로 지정한 디렉토리의 존재 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [59-START] >> $RESULT_FILE 2>&1
cat /etc/passwd | awk -F: '$3>=500 {print $0}' > tmp_59_1.txt
cat tmp_59_1.txt | awk -F: '{print $6}' > tmp_59_2.txt
touch tmp_59_3.txt
for i in `cat tmp_59_2.txt`
	do
		if [ -d $i ]; then echo $i >> tmp_59_3.txt; else true; fi
done
if [ `diff tmp_59_2.txt tmp_59_3.txt | wc -l` -eq 0 ]
	then
		echo "★ 홈디렉토리가 존재하지 않는 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [59-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-59]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 홈디렉토리가 존재하지 않는 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		diff tmp_59_2.txt tmp_59_3.txt | grep "<" | awk '{print $2}' > tmp_59_4.txt
		for i in `cat tmp_59_4.txt`
			do
				cat /etc/passwd | grep $i | awk -F: '{print "계정  "$1"  의 홈디렉토리  "$6"  가 존재하지 않음"}' >> $RESULT_FILE 2>&1
		done
		echo [59-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-59]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_59_1.txt
rm -rf tmp_59_2.txt
rm -rf tmp_59_3.txt
rm -rf tmp_59_4.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-60]숨겨진 파일 및 디렉토리 검색 및 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-60]숨겨진 파일 및 디렉토리 검색 및 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [60-START] >> $RESULT_FILE 2>&1
find /tmp/ | grep "/\." > tmp_60_1.txt
if [ `cat tmp_60_1.txt | wc -l` -eq 0 ]
	then
		echo "★ /tmp 디렉토리에 숨김 속성 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-60]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ /tmp 디렉토리에 숨김 속성 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_60_1.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_60_1.txt | wc -l >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-60]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_60_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-61]ssh 원격접속 허용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-61]ssh 원격접속 허용  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [61-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "sshd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SSH 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-61]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		echo "★ SSH 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "sshd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-61]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-62]ftp 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-62]ftp 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [62-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [62-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-62]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ FTP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "ftpd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [62-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-62]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-63]ftp 계정 shell 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-63]ftp 계정 shell 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [63-START] >> $RESULT_FILE 2>&1
cat /etc/passwd | grep -w "^ftp" > tmp_63_1.txt
if [ `cat tmp_63_1.txt | wc -l` -eq 0 ]
	then
		echo "★ /etc/passwd 파일에 'ftp' 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [63-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-63]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_63_1.txt | awk -F: '{print $7}' | egrep -v "false|nologin|null|halt|sync|shutdown" | wc -l` -eq 0 ]
			then
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_63_1.txt >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_63_1.txt >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_63_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-64]Ftpusers 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-64]Ftpusers 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [64-START] >> $RESULT_FILE 2>&1
find /etc -name "ftpusers" -exec ls -l {} \; > tmp_64_1.txt
if [ `cat tmp_64_1.txt | wc -l` -eq 0 ]
	then
		echo "★ ftpusers 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [64-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-64]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_64_1.txt | grep "^.....-----" | awk '$3=="root"' | wc -l` -eq 0 ]
			then
				echo "★ ftpusers 파일의 소유자 및 퍼미션이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_64_1.txt >> $RESULT_FILE 2>&1
				echo [64-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-64]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ ftpusers 파일의 소유자 및 퍼미션이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_64_1.txt >> $RESULT_FILE 2>&1
				echo [64-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-64]Result : GOOD >> $RESULT_FILE 2>&1				
		fi
fi
rm -rf cat tmp_64_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-65]Ftpusers 파일 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-65]Ftpusers 파일 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [65-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [65-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "ftpusers" -exec ls -l {} \; > tmp_65_1.txt
		if [ `cat tmp_65_1.txt | wc -l` -eq 0 ]
			then
				echo "★ ftpusers 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [65-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
			else
				find /etc -name "ftpusers" -exec cat {} \; > tmp_65_2.txt
				if [ `cat tmp_65_2.txt | grep "root" | grep -v "^ *#" | wc -l` -gt 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재함" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_65_1.txt >> $RESULT_FILE 2>&1
						cat tmp_65_2.txt >> $RESULT_FILE 2>&1
						echo [65-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_65_1.txt >> $RESULT_FILE 2>&1
						cat tmp_65_2.txt >> $RESULT_FILE 2>&1
						echo [65-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-65]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi		
rm -rf tmp_65_1.txt
rm -rf tmp_65_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-66]at 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-66]at 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [66-START] >> $RESULT_FILE 2>&1
ls -l /etc/ | egrep "at.deny|at.allow" > tmp_66_1.txt
if [ `cat tmp_66_1.txt | wc -l` -eq 0 ]
	then
		echo "★ at.deny, at.allow 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [66-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-66]Result : GOOD >> $RESULT_FILE 2>&1
	else
		cat tmp_66_1.txt | grep "^.....-----" | awk '$3=="root"' > tmp_66_2.txt
		if [ `diff tmp_66_1.txt tmp_66_2.txt | wc -l` -eq 0 ]
			then
				echo "★ at 파일의 소유자 및 퍼미션(640)이 적절하게 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_66_1.txt >> $RESULT_FILE 2>&1
				echo [66-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-66]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ cron 파일의 소유자 및 퍼미션(640)이 적절하게 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_66_1.txt >> $RESULT_FILE 2>&1
				echo [66-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-66]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf cat tmp_66_1.txt
rm -rf cat tmp_66_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-67]SNMP 서비스 구동 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-67]SNMP 서비스 구동 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [67-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [67-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-67]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ SNMP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "snmpd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [67-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-67]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-68]SNMP 서비스 커뮤니티스트링의 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-68]SNMP 서비스 커뮤니티스트링의 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [68-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [68-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-68]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "snmpd.conf" -exec cat {} \; > tmp_68_1.txt
		if [ `cat tmp_68_1.txt | wc -l` -gt 0 ]
			then
				if [ `cat tmp_68_1.txt | grep "public" | grep -v "^ *#" | wc -l` -eq 0 ]
					then
						echo "★ SNMP Community String이 임의의 값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_68_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [68-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-68]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ SNMP Community String이 기본값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_68_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [68-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-68]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ SNMP 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : MANUAL >> $RESULT_FILE 2>&1
		fi						
fi
rm -rf tmp_68_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-69]로그온 시 경고 메시지 제공
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-69]로그온 시 경고 메시지 제공  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [69-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/issue.net | wc -l` -gt 2 ]
	then
		if [ `cat /etc/motd | wc -l` -gt 0 ]
			then
				echo "★ /etc/issue.net, /etc/motd 파일에 경고 메시지가 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				echo "1) /etc/issue.net 파일 내용" >> $RESULT_FILE 2>&1
				cat /etc/issue.net >> $RESULT_FILE 2>&1
				echo "2) /etc/motd 파일 내용" >> $RESULT_FILE 2>&1
				cat /etc/motd >> $RESULT_FILE 2>&1
				echo [69-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-69]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/motd 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [69-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		if [ `cat /etc/motd | wc -l` -gt 0 ]
			then
				echo "★ /etc/issue.net 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [69-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/issue.net, /etc/motd 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [69-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-70]NFS 설정 파일 접근 권한 
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-70]NFS 설정 파일 접근 권한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [70-START] >> $RESULT_FILE 2>&1
if [ -f /etc/exports ]
	then
		if [ `ls -l /etc/exports | grep "^.....--.--" | wc -l` -eq 0 ]
			then
				echo "★ /etc/exports 파일의 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/exports >> $RESULT_FILE 2>&1
				echo [70-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-70]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/exports 파일의 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/exports >> $RESULT_FILE 2>&1
				echo [70-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-70]Result : GOOD >> $RESULT_FILE 2>&1
		fi	
	else
		echo "★ /etc/exports 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [70-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-70]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-71]expn, vrfy 명령어 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-71]expn, vrfy 명령어 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [71-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [71-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-71]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [71-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-71]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_71.txt \;			
				cat tmp_71.txt | grep -i "O PrivacyOptions" > tmp_71_1.txt
				if [ `cat tmp_71_1.txt | grep -v "^ *#" | grep "noexpn" | grep "novrfy" | wc -l` -eq 0 ]
					then
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_71_1.txt >> $RESULT_FILE 2>&1
						echo [71-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-71]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_71_1.txt >> $RESULT_FILE 2>&1
						echo [71-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-71]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_71.txt
rm -rf tmp_71_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-73]정책에 따른 시스템 로깅 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-73]정책에 따른 시스템 로깅 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [73-START] >> $RESULT_FILE 2>&1
if [ -f /etc/syslog.conf ]
	then
		cat /etc/syslog.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_73_1.txt
	else
		if [ -f /etc/rsyslog.conf ]
			then
				cat /etc/rsyslog.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_73_1.txt
			else
				echo "★ (r)syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [73-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-73]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
fi
if [ `cat tmp_73_1.txt | egrep -w "cron.\*|authpriv.\*|\*.info" | wc -l` -eq 3 ]
	then
		echo "★ (r)syslog.conf 설정이 적절하게 설정됨 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_73_1.txt >> $RESULT_FILE 2>&1
		echo [73-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-73]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 아래 현황을 기반으로 수동분석 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_73_1.txt >> $RESULT_FILE 2>&1
		echo [73-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-73]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf tmp_73_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-74]정책에 따른 시스템 로깅 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-74]정책에 따른 시스템 로깅 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [74-START] >> $RESULT_FILE 2>&1
if [ -f /etc/rsyslog.d/50-default.conf ]
	then
		cat /etc/rsyslog.d/50-default.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_74_1.txt
	else
		if [ -f /etc/rsyslog.d/50-default.conf ]
			then
				cat /etc/rsyslog.d/50-default.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_74_1.txt
			else
				echo "★ (r)syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [74-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-74]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
fi
if [ `cat tmp_73_1.txt | egrep -w "cron.\*|authpriv.\*|\*.info" | wc -l` -eq 3 ]
	then
		echo "★ (r)syslog.conf 설정이 적절하게 설정됨 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_74_1.txt >> $RESULT_FILE 2>&1
		echo [74-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-74]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 아래 현황을 기반으로 수동분석 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_74_1.txt >> $RESULT_FILE 2>&1
		echo [74-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-74]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf tmp_74_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Version ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
uname -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/issue >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ ping test ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ping -c 3 www.google.com >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Interface ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ifconfig -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/passwd ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/passwd  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/shadow ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/shadow  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Socket ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
netstat -anp | head -200 >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Daemon ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "1) ps -ef" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ps -ef >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "2) chkconfig --list" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
chkconfig --list >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Iptables]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
iptables -L >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ TCP Wrapper]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "1) /etc/hosts.deny" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/hosts.deny >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "2) /etc/hosts.allow" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/hosts.allow >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Ubuntu Log]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat  /etc/rsyslog.d/50-default.conf >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ PW setting]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "1) common-password" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat  /etc/pam.d/common-password  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "2) common-auth" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat  /etc/pam.d/common-auth  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "3) pwquailty.conf" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/security/pwquailty.conf >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "4) password-auth" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/pam.d/password-auth >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "5) system-auth" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/pam.d/system-auth >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo ""
echo "==============================  END  ==============================" 

exit;;





2)
# Apache

echo ""
echo ""


IP=`ifconfig -a | grep  "inet addr" | head -1 | awk '{print $2}' | awk -F: '{print $2}'`


RESULT_FILE=./Apache@@`hostname`@@$IP.txt


# Apache 설정파일 입력

echo "Input a apache main configuration file. (ex. /usr/local/httpd/conf/httpd.conf)"
while true
do 
	echo -n "Input path : " 
	read HTTP_CONF_INP
	if [ "$HTTP_CONF_INP" ]
		then
			if [ -f "$HTTP_CONF_INP" ]
				then 
					break
				else
					echo "Wrong path. Please retry."
					echo " "
			fi
	elif [ -z "$HTTP_CONF_INP"]
		then
			break
	else
		echo "Wrong path. Please retry."
		echo " "
	fi
done
echo " "

# Apache 홈 확인

HTTP_ROOT=`grep -i "ServerRoot" $HTTP_CONF_INP | grep -v "#" | head -1 | awk -F\" '{print $2}'`
HTTP_DOC_ROOT=`grep -i "DocumentRoot" $HTTP_CONF_INP | grep -v "#" | head -1 | awk -F\" '{print $2}'`

# Apache 추가 설정 파일 확인

if [ `grep -i "^Include" $HTTP_CONF_INP | grep -v "#" | wc -l` -eq 0 ]
	then
		cat $HTTP_CONF_INP > http_conf.txt
	else
		cat $HTTP_CONF_INP > http_conf.txt
		for a in `grep -i "^Include" $HTTP_CONF_INP | grep -v "#" | awk '{print $2}'`
			do 
				cat $HTTP_ROOT/$a >> http_conf.txt 
		done
fi

HTTP_CONF=./http_conf.txt


# 타이틀
echo "===============  Apache Security Check  ===============" > $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "Copyright (c) 2016 KIITS Co. Ltd. All right Reserved" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo ""
echo "============================== START ==============================" 
echo ""

# [WA-1] Apache 디렉토리 리스팅 제거
echo "[WA-1] Apache 디렉토리 리스팅 제거"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-1] Apache 디렉토리 리스팅 제거"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [1-START] >> $RESULT_FILE 2>&1
if [ `grep -w "Indexes" $HTTP_CONF_INP | grep -v "#" | wc -l` -eq 0 ]
	then
		echo "★ Indexes 옵션이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [1-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-1]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Indexes 옵션이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep -inw "Indexes" $HTTP_CONF_INP | grep -v "#" >> $RESULT_FILE 2>&1
		echo [1-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-1]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


# [WA-2] Apache 웹 프로세스 권한 제한
echo "[WA-2] Apache 웹 프로세스 권한 제한"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-2] Apache 웹 프로세스 권한 제한"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [2-START] >> $RESULT_FILE 2>&1
egrep -in "^User" $HTTP_CONF > tmp_2.txt
egrep -in "^Group" $HTTP_CONF >> tmp_2.txt
if [ `cat tmp_2.txt | grep -w "root" | wc -l` -eq 0 ]
	then
		echo "★ Apache 구동 계정이 root가 아닌 일반 계정임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_2.txt >> $RESULT_FILE 2>&1
		echo [2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-2]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Apache 데몬이 root 계정으로 구동됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_2.txt >> $RESULT_FILE 2>&1
		echo [2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-3] Apache 상위 디렉토리 접근 금지
echo "[WA-3] Apache 상위 디렉토리 접근 금지"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-3] Apache 상위 디렉토리 접근 금지"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [3-START] >> $RESULT_FILE 2>&1
grep -win "AllowOverride" $HTTP_CONF | grep -v "#" > tmp_3.txt
if [ `cat tmp_3.txt | wc -l` -eq 0 ]
	then
		echo "★ AllowOverride 설정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [3-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_3.txt | grep -wi "None" | wc -l` -eq 0 ]
			then
				echo "★ AllowOverride None 설정이 존재하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_3.txt >> $RESULT_FILE 2>&1
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-3]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ AllowOverride None 설정이 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_3.txt >> $RESULT_FILE 2>&1
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-4] Apache 불필요한 파일 제거
echo "[WA-4] Apache 불필요한 파일 제거"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-4] Apache 불필요한 파일 제거"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [4-START] >> $RESULT_FILE 2>&1
if [ `ls -ld $HTTP_ROOT/manual | wc -l` -eq 0 ]
	then
		if [ `ls -ld $HTTP_DOC_ROOT/manual | wc -l` -eq 0 ]
			then
				echo "★ 불필요한 manual 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
				echo [4-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-4]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 불필요한 manual 파일이 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -ld $HTTP_DOC_ROOT/manual >> $RESULT_FILE 2>&1
				echo [4-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ 불필요한 manual 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ls -ld $HTTP_ROOT/manual >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-5] Apache 링크 사용금지
echo "[WA-5] Apache 링크 사용금지"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-5] Apache 링크 사용금지"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [5-START] >> $RESULT_FILE 2>&1
if [ `grep -wi "FollowSymLinks" $HTTP_CONF_INP | grep -v "#" | wc -l` -eq 0 ]
	then
		echo "★ FollowSymLinks 옵션이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-5]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ FollowSymLinks 옵션이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep -inw "FollowSymLinks" $HTTP_CONF_INP | grep -v "#" >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-5]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-6] Apache 파일 업로드 및 다운로드 제한
echo "[WA-6] Apache 파일 업로드 및 다운로드 제한"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-6] Apache 파일 업로드 및 다운로드 제한"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [6-START] >> $RESULT_FILE 2>&1
if [ `grep -wi "LimitRequestBody" $HTTP_CONF | grep -v "#" | wc -l` -eq 0 ]
	then
		echo "★ LimitRequestBody 옵션이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-6]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		echo "★ LimitRequestBody 옵션이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep -inw "LimitRequestBody" $HTTP_CONF | grep -v "#" >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-6]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-7] Apache 웹 서비스 영역의 분리
echo "[WA-7] Apache 웹 서비스 영역의 분리"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-7] Apache 웹 서비스 영역의 분리"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [7-START] >> $RESULT_FILE 2>&1
if [ `echo $HTTP_DOC_ROOT | egrep -w "/usr/local/apache/htdocs|/var/www/html" | wc -l` -eq 0 ]
	then
		echo "★ DocumentRoot로 기본경로를 사용하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $HTTP_DOC_ROOT >> $RESULT_FILE 2>&1
		echo [7-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-7]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ DocumentRoot로 기본경로를 사용함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $HTTP_DOC_ROOT >> $RESULT_FILE 2>&1
		echo [7-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-7]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-8] Apache 웹 서비스 정보 숨김
echo "[WA-8] Apache 웹 서비스 정보 숨김"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-8] Apache 웹 서비스 정보 숨김"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [8-START] >> $RESULT_FILE 2>&1
if [ `grep -wi "servertokens" $HTTP_CONF | grep -v "#" | wc -l` -eq 0 ]
	then
		echo "★ ServerTokens 옵션이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [8-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-8]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		if [ `grep -wi "servertokens" $HTTP_CONF | grep -v "#" | grep -wi "prod" | wc -l` -eq 0 ]
			then
				echo "★ ServerTokens 옵션이 Prod로 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [8-END] >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -wi "servertokens" $HTTP_CONF | grep -v "#" >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-8]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ ServerTokens 옵션이 Prod로 설정됨" >> $RESULT_FILE 2>&1
				echo [8-END] >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -wi "servertokens" $HTTP_CONF | grep -v "#" >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-8]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[ HTTP CONF ]"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat -n $HTTP_CONF >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Version ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
uname -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/issue >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Interface ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ifconfig -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Daemon ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "1) ps -ef" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ps -ef >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "2) chkconfig --list" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
chkconfig --list >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo ""
echo "============================== END ==============================" 




# 임시 파일 삭제
rm -rf ./http_conf.txt

unset HTTP_ROOT
unset HTTP_CONF_INP
unset HTTP_CONF
unset HTTP_DOC_ROOT


exit;;


3)
#Linux Server + Apache

echo ""
echo ""


IP=`ifconfig -a | grep  "inet addr" | head -1 | awk '{print $2}' | awk -F: '{print $2}'`


RESULT_FILE=./Apache@@`hostname`@@$IP.txt


# Apache 설정파일 입력

echo "Input a apache main configuration file. (ex. /usr/local/httpd/conf/httpd.conf)"
while true
do 
	echo -n "Input path : " 
	read HTTP_CONF_INP
	if [ "$HTTP_CONF_INP" ]
		then
			if [ -f "$HTTP_CONF_INP" ]
				then 
					break
				else
					echo "Wrong path. Please retry."
					echo " "
			fi
	elif [ -z "$HTTP_CONF_INP"]
		then
			break
	else
		echo "Wrong path. Please retry."
		echo " "
	fi
done
echo " "

# Apache 홈 확인

HTTP_ROOT=`grep -i "ServerRoot" $HTTP_CONF_INP | grep -v "#" | head -1 | awk -F\" '{print $2}'`
HTTP_DOC_ROOT=`grep -i "DocumentRoot" $HTTP_CONF_INP | grep -v "#" | head -1 | awk -F\" '{print $2}'`

# Apache 추가 설정 파일 확인

if [ `grep -i "^Include" $HTTP_CONF_INP | grep -v "#" | wc -l` -eq 0 ]
	then
		cat $HTTP_CONF_INP > http_conf.txt
	else
		cat $HTTP_CONF_INP > http_conf.txt
		for a in `grep -i "^Include" $HTTP_CONF_INP | grep -v "#" | awk '{print $2}'`
			do 
				cat $HTTP_ROOT/$a >> http_conf.txt 
		done
fi

HTTP_CONF=./http_conf.txt


# 타이틀
echo "===============  Apache Security Check  ===============" > $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "Copyright (c) 2016 KIITS Co. Ltd. All right Reserved" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo ""
echo "============================== START ==============================" 
echo ""


# [WA-1] Apache 디렉토리 리스팅 제거
echo "[WA-1] Apache 디렉토리 리스팅 제거"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-1] Apache 디렉토리 리스팅 제거"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [1-START] >> $RESULT_FILE 2>&1
if [ `grep -w "Indexes" $HTTP_CONF_INP | grep -v "#" | wc -l` -eq 0 ]
	then
		echo "★ Indexes 옵션이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [1-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-1]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Indexes 옵션이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep -inw "Indexes" $HTTP_CONF_INP | grep -v "#" >> $RESULT_FILE 2>&1
		echo [1-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-1]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


# [WA-2] Apache 웹 프로세스 권한 제한
echo "[WA-2] Apache 웹 프로세스 권한 제한"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-2] Apache 웹 프로세스 권한 제한"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [2-START] >> $RESULT_FILE 2>&1
egrep -in "^User" $HTTP_CONF > tmp_2.txt
egrep -in "^Group" $HTTP_CONF >> tmp_2.txt
if [ `cat tmp_2.txt | grep -w "root" | wc -l` -eq 0 ]
	then
		echo "★ Apache 구동 계정이 root가 아닌 일반 계정임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_2.txt >> $RESULT_FILE 2>&1
		echo [2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-2]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Apache 데몬이 root 계정으로 구동됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_2.txt >> $RESULT_FILE 2>&1
		echo [2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-3] Apache 상위 디렉토리 접근 금지
echo "[WA-3] Apache 상위 디렉토리 접근 금지"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-3] Apache 상위 디렉토리 접근 금지"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [3-START] >> $RESULT_FILE 2>&1
grep -win "AllowOverride" $HTTP_CONF | grep -v "#" > tmp_3.txt
if [ `cat tmp_3.txt | wc -l` -eq 0 ]
	then
		echo "★ AllowOverride 설정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [3-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_3.txt | grep -wi "None" | wc -l` -eq 0 ]
			then
				echo "★ AllowOverride None 설정이 존재하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_3.txt >> $RESULT_FILE 2>&1
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-3]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ AllowOverride None 설정이 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_3.txt >> $RESULT_FILE 2>&1
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-4] Apache 불필요한 파일 제거
echo "[WA-4] Apache 불필요한 파일 제거"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-4] Apache 불필요한 파일 제거"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [4-START] >> $RESULT_FILE 2>&1
if [ `ls -ld $HTTP_ROOT/manual | wc -l` -eq 0 ]
	then
		if [ `ls -ld $HTTP_DOC_ROOT/manual | wc -l` -eq 0 ]
			then
				echo "★ 불필요한 manual 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
				echo [4-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-4]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 불필요한 manual 파일이 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -ld $HTTP_DOC_ROOT/manual >> $RESULT_FILE 2>&1
				echo [4-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ 불필요한 manual 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ls -ld $HTTP_ROOT/manual >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-5] Apache 링크 사용금지
echo "[WA-5] Apache 링크 사용금지"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-5] Apache 링크 사용금지"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [5-START] >> $RESULT_FILE 2>&1
if [ `grep -wi "FollowSymLinks" $HTTP_CONF_INP | grep -v "#" | wc -l` -eq 0 ]
	then
		echo "★ FollowSymLinks 옵션이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-5]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ FollowSymLinks 옵션이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep -inw "FollowSymLinks" $HTTP_CONF_INP | grep -v "#" >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-5]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-6] Apache 파일 업로드 및 다운로드 제한
echo "[WA-6] Apache 파일 업로드 및 다운로드 제한"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-6] Apache 파일 업로드 및 다운로드 제한"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [6-START] >> $RESULT_FILE 2>&1
if [ `grep -wi "LimitRequestBody" $HTTP_CONF | grep -v "#" | wc -l` -eq 0 ]
	then
		echo "★ LimitRequestBody 옵션이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-6]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		echo "★ LimitRequestBody 옵션이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep -inw "LimitRequestBody" $HTTP_CONF | grep -v "#" >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-6]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-7] Apache 웹 서비스 영역의 분리
echo "[WA-7] Apache 웹 서비스 영역의 분리"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-7] Apache 웹 서비스 영역의 분리"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [7-START] >> $RESULT_FILE 2>&1
if [ `echo $HTTP_DOC_ROOT | egrep -w "/usr/local/apache/htdocs|/var/www/html" | wc -l` -eq 0 ]
	then
		echo "★ DocumentRoot로 기본경로를 사용하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $HTTP_DOC_ROOT >> $RESULT_FILE 2>&1
		echo [7-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-7]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ DocumentRoot로 기본경로를 사용함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $HTTP_DOC_ROOT >> $RESULT_FILE 2>&1
		echo [7-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-7]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



# [WA-8] Apache 웹 서비스 정보 숨김
echo "[WA-8] Apache 웹 서비스 정보 숨김"
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[WA-8] Apache 웹 서비스 정보 숨김"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [8-START] >> $RESULT_FILE 2>&1
if [ `grep -wi "servertokens" $HTTP_CONF | grep -v "#" | wc -l` -eq 0 ]
	then
		echo "★ ServerTokens 옵션이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [8-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [WA-8]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		if [ `grep -wi "servertokens" $HTTP_CONF | grep -v "#" | grep -wi "prod" | wc -l` -eq 0 ]
			then
				echo "★ ServerTokens 옵션이 Prod로 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [8-END] >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -wi "servertokens" $HTTP_CONF | grep -v "#" >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-8]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ ServerTokens 옵션이 Prod로 설정됨" >> $RESULT_FILE 2>&1
				echo [8-END] >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -wi "servertokens" $HTTP_CONF | grep -v "#" >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [WA-8]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo "[ HTTP CONF ]"  >> $RESULT_FILE 2>&1
echo "=======================================================================" 	>> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat -n $HTTP_CONF >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Version ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
uname -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/issue >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Interface ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ifconfig -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Daemon ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "1) ps -ef" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ps -ef >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "2) chkconfig --list" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
chkconfig --list >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo ""


# 임시 파일 삭제
rm -rf ./http_conf.txt

unset HTTP_ROOT
unset HTTP_CONF_INP
unset HTTP_CONF
unset HTTP_DOC_ROOT


# Server

RESULT_FILE=./Linux@@`hostname`@@$IP.txt

echo "===============  Linux Server Security Check  ===============" > $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "Copyright (c) 2016 KIITS Co. Ltd. All right Reserved" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-1]root 계정 원격 접속 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-1]root 계정 원격 접속 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [1-START] >> $RESULT_FILE 2>&1
if [ `find /etc -type f -name "sshd_config" | wc -l` -eq 0 ]
	then
		echo "★ sshd_config 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [1-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-1]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SSHCONFIG=`find /etc -type f -name "sshd_config"`
		if [ `grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "#" | grep -i "no" | wc -l` -eq 0 ]
			then
				echo "★ root 계정 원격 접속이 제한되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : VULNERABLE >> $RESULT_FILE 2>&1
				
			else
				echo "★ root 계정 원격 접속이 제한됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-2]패스워드 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-2]패스워드 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [2-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "system-auth" | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-2]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "system-auth"`
		if [ `grep -i "password" $SYSAUTH | grep "requisite" | grep "lcredit" | grep "dcredit" | grep "ocredit" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 복잡성 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 패스워드 복잡성 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-2-2]패스워드 복잡성 설정u
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-2-2]패스워드 복잡성 설정u  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [2-2-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "common-auth" | wc -l` -eq 0 ]
	then
		echo "★ common-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [2-2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-2-2]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "common-auth"`
		if [ `grep -i "password" $SYSAUTH | grep "requisite" | grep "lcredit" | grep "dcredit" | grep "ocredit" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 복잡성 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 패스워드 복잡성 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2-2]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-3]계정 잠금 임계값 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-3]계정 잠금 임계값 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [3-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "system-auth" | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [3-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-3]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "system-auth"`
		if [ `grep -i "pam_tally2.so" $SYSAUTH | grep -i "deny" | wc -l` -eq 0 ]
			then
				echo "★ 계정 잠금 임계값 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTH >> $RESULT_FILE 2>&1 
				grep -i "^password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 계정 잠금 임계값 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTH >> $RESULT_FILE 2>&1 
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1			
				echo [U-3]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-3-2]계정 잠금 임계값 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-3-2]계정 잠금 임계값 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [3-2-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "common-auth" | wc -l` -eq 0 ]
	then
		echo "★ common-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [3-2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-3-2]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "common-auth"`
		if [ `grep -i "pam_tally2.so" $SYSAUTH | grep -i "deny" | wc -l` -eq 0 ]
			then
				echo "★ 계정 잠금 임계값 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTH >> $RESULT_FILE 2>&1 
				grep -i "^password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [3-2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-3-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 계정 잠금 임계값 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTH >> $RESULT_FILE 2>&1 
				echo [3-2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1			
				echo [U-3-2]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-4]패스워드 파일 보호
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-4]패스워드 파일 보호  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [4-START] >> $RESULT_FILE 2>&1
if [ `head -1 /etc/passwd | awk -F: '{print $2}' | egrep "^x" | wc -c` -eq 2 ]
	then
		echo "★ 패스워드를 /etc/passwd 파일에 저장하지 않고 별도의 파일에 저장함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		head -1 /etc/passwd >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-4]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 패스워드를 /etc/passwd 파일에 저장함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		head -1 /etc/passwd >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1	
		echo [U-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-05]root 홈, 패스 디렉터리 권한 및 패스 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-05]root 홈, 패스 디렉터리 권한 및 패스 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [05-START] >> $RESULT_FILE 2>&1
if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
	then
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [05-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-05]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [05-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-05]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-06]파일 및 디렉터리 소유자 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-06]파일 및 디렉터리 소유자 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [06-START] >> $RESULT_FILE 2>&1
ls -l /home | awk '{print $3}' | grep "^[0-9]" > tmp_06_1.txt
for i in `cat tmp_17_1.txt`; do ls -l /home | grep -w $i >> tmp_06_2.txt; done
if [ -f tmp_06_2.txt ]
	then
		echo "★ /home 디렉토리에 소유자가 존재하지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_06_2.txt >> $RESULT_FILE 2>&1
		echo [06-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-06]Result : VULNERABLE >> $RESULT_FILE 2>&1		
	else
		echo "★ /home 디렉토리에 소유자가 존재하지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [06-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-06]Result : GOOD >> $RESULT_FILE 2>&1
fi
rm -rf tmp_06_1.txt
rm -rf tmp_06_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-07]/etc/passwd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-07]/etc/passwd 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [07-START] >> $RESULT_FILE 2>&1
if [ `ls -alL /etc/passwd | grep "^...-.--.--" | awk '$3=="root"' | wc -l` -eq 1 ]
  then
	echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	ls -alL /etc/passwd >> $RESULT_FILE 2>&1
	echo [07-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-07]Result : GOOD >> $RESULT_FILE 2>&1
 else
	echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	ls -alL /etc/passwd >> $RESULT_FILE 2>&1
	echo [07-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-07]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-08]/etc/shadow 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-08]/etc/shadow 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [08-START] >> $RESULT_FILE 2>&1
if [ `ls -alL /etc/shadow | grep "^.-.-------" | awk '$3=="root"' | wc -l` -eq 1 ]
  then
	echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	ls -alL /etc/shadow >> $RESULT_FILE 2>&1
	echo [08-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-08]Result : GOOD >> $RESULT_FILE 2>&1
 else
	echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	ls -alL /etc/shadow >> $RESULT_FILE 2>&1
	echo [08-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-08]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-09]/etc/hosts 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-09]/etc/hosts 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [09-START] >> $RESULT_FILE 2>&1
if [ -f /etc/hosts ]
	then
		if [ `ls -alL /etc/hosts | grep "^....------" | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/hosts >> $RESULT_FILE 2>&1
				echo [09-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-09]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/hosts >> $RESULT_FILE 2>&1
				echo [09-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-09]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/hosts 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [09-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-09]Result : N/A >> $RESULT_FILE 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "[U-10]/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
echo "============================================================" >> $RESULT_FILE 2>&1
echo "[U-10]/etc/(x)inetd.conf 파일 소유자 및 권한 설정"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [10-START] >> $RESULT_FILE 2>&1
if [ -f /etc/xinetd.conf ]
	then
		if [ `ls -alL /etc/xinetd.conf | grep "^....------" | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/xinetd.conf >> $RESULT_FILE 2>&1
				echo [10-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-10]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/xinetd.conf >> $RESULT_FILE 2>&1
				echo [10-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-10]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		if [ -f /etc/inetd.conf ]
			then
				if [ `ls -alL /etc/inetd.conf | grep "^....------" | awk '$3=="root"' | wc -l` -eq 1 ]
					then
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ls -alL /etc/inetd.conf >> $RESULT_FILE 2>&1
						echo [10-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-10]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ls -alL /etc/inetd.conf >> $RESULT_FILE 2>&1
						echo [10-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-10]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi				
			else
				echo "★ /etc/(x)inetd.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [10-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-10]Result : GOOD >> $RESULT_FILE 2>&1 
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-11]/etc/syslog.conf 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-11]/etc/syslog.conf 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [11-START] >> $RESULT_FILE 2>&1
if [ -f /etc/syslog.conf ]
	then
		if [ `ls -alL /etc/syslog.conf | grep "^...-.--.--" | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/syslog.conf 파일의 소유자 및 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/syslog.conf >> $RESULT_FILE 2>&1
				echo [11-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-11]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/syslog.conf 파일의 소유자 및 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/syslog.conf >> $RESULT_FILE 2>&1
				echo [11-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-11]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		if [ -f /etc/rsyslog.conf ]
			then
				if [ `ls -alL /etc/rsyslog.conf | grep "^...-.--.--" | awk '$3=="root"' | wc -l` -eq 1 ]
					then
						echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ls -alL /etc/rsyslog.conf >> $RESULT_FILE 2>&1
						echo [11-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1	
						echo [U-11]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ls -alL /etc/rsyslog.conf >> $RESULT_FILE 2>&1
						echo [11-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-11]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ /etc/syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [11-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-11]Result : N/A >> $RESULT_FILE 2>&1 
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-12]/etc/services 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-12]/etc/services 파일 소유자 및 권한 설정 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [12-START] >> $RESULT_FILE 2>&1
if [ -f /etc/services ]
	then
		if [ `ls -alL /etc/services | grep "^...-.--.--" | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/services >> $RESULT_FILE 2>&1
				echo [12-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-12]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/services >> $RESULT_FILE 2>&1
				echo [12-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-12]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/services 파일이 없음" >> $RESULT_FILE 2>&1
		echo [12-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-12]Result : N/A >> $RESULT_FILE 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-13]SUID, SGID, Sticky bit 설정 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-13]SUID, SGID, Sticky bit 설정 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [13-START] >> $RESULT_FILE 2>&1
FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"
for check_file in $FILES
	do
    if [ -f $check_file ]
		then
			if [ -g $check_file -o -u $check_file ]
				then
					echo `ls -alL $check_file` >> tmp_13.txt
				else
				:
			fi
		else
		:
    fi
done
if [ -f tmp_13.txt ]
	then
		echo "★ 점검 파일 중 SUID, SGID가 설정된 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_13.txt >> $RESULT_FILE 2>&1
		echo [13-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-13]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		echo "★ 점검 파일 중 SUID, SGID가 설정된 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [13-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-13]Result : GOOD >> $RESULT_FILE 2>&1
fi
rm -rf tmp_13.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [14-START] >> $RESULT_FILE 2>&1
if [ -f /etc/profile ]
	then
		if [ `ls -alL /etc/profile | grep "^.....-..-." | awk '$3=="root"' | wc -l` -eq 1 ]
			then
				echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -al /etc/profile >> $RESULT_FILE 2>&1
				echo [14-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-14]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -al /etc/profile >> $RESULT_FILE 2>&1
				echo [14-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-14]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/profile 파일이 없음" >> $RESULT_FILE 2>&1
		echo [14-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-14]Result : N/A >> $RESULT_FILE 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-15]world writable 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-15]world writable 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [15-START] >> $RESULT_FILE 2>&1
find /etc -perm -2 -a -not -type l -ls > tmp_15.txt
if [ `cat tmp_15.txt | wc -l` -eq 0 ]
	then
		echo "★ /etc 디렉토리 하위에 Others에 쓰기 권한이 부여된 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [15-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-15]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ /etc 디렉토리 하위에 Others에 쓰기 권한이 부여된 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_15.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_15.txt | wc -l >> $RESULT_FILE 2>&1
		echo [15-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-15]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_15.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-16]/dev에 존재하지 않는 device 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-16]/dev에 존재하지 않는 device 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [16-START] >> $RESULT_FILE 2>&1
find /dev -type f -exec ls -l {} \; > tmp_16.txt
if [ `cat tmp_16.txt | wc -l` -eq 0 ]
	then
		echo "★ /dev 디렉토리에 major, minor nubmer를 가지지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [16-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-16]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ /dev 디렉토리에 major, minor nubmer를 가지지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_16.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_16.txt | wc -l >> $RESULT_FILE 2>&1
		echo [16-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-16]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_16.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [17-START] >> $RESULT_FILE 2>&1
ls -l /home/ | grep -v "+found" | sed -n '2,$p' | awk '{print $9}' > tmp_17_1.txt
for i in `cat tmp_17_1.txt`; do ls -al /home/$i/.rhosts; done 2>/dev/null > tmp_17_2.txt
if [ -f /etc/hosts.equiv ]; then ls -l /etc/hosts.equiv >> tmp_17_2.txt; else true; fi 
if [ `cat tmp_17_2.txt | wc -l` -eq 0 ]
	then
		echo "★ .rhosts, hosts.equiv 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [17-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-17]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_17_2.txt | wc -l` -eq `cat tmp_17_2.txt | grep "^....------" | wc -l` ]
			then
				for i in `cat tmp_17_2.txt | awk '{print $9}'`; do cat $i; done >> tmp_17_3.txt
				if [ `cat tmp_17_3.txt | grep "\+" | wc -l` -eq 0 ] 
					then
						echo "★ .rhosts, hosts.equiv 파일의 퍼미션 및 설정이 적절하게 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
						echo [17-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-17]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ .rhosts, hosts.equiv 파일의 설정이 적절하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
						echo [17-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ .rhosts, hosts.equiv 파일의 퍼미션이 적절하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
				echo [17-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_17_1.txt
rm -rf tmp_17_2.txt				
rm -rf tmp_17_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-18]접속 IP 및 포트 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-18]접속 IP 및 포트 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [18-START] >> $RESULT_FILE 2>&1
if [ -f /etc/hosts.deny ]
	then
		if [ `cat /etc/hosts.deny | grep -v "#" | grep -E "ALL:.*ALL" | wc -l` -eq 0 ]
			then
				echo "★ /etc/hosts.deny 파일에 ALL Deny 설정이 존재하지 않음" >> $RESULT_FILE 2>&1
				echo [18-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-18]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/hosts.deny 파일에 ALL Deny 설정이 적용됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/hosts.deny >> $RESULT_FILE 2>&1
				cat /etc/hosts.deny | grep -v "#" >> $RESULT_FILE 2>&1
				ls -l /etc/hosts.allow >> $RESULT_FILE 2>&1
				cat /etc/hosts.allow | grep -v "#" >> $RESULT_FILE 2>&1
				echo [18-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-18]Result : GOOD >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/hosts.deny 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [18-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-18]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-19]Finger 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-19]Finger 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [19-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "finger" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Finger 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Finger 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "finger" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-20]Anonymous FTP 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-20]Anonymous FTP 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [20-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [20-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "vsftpd.conf" -exec cat {} \; > tmp_20_1.txt
		if [ `cat tmp_20_1.txt | wc -l` -eq 0 ]
			then
				if [ `cat /etc/passwd | egrep -w "ftp|anonymous" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재하지 않음 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재함 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat /etc/passwd | egrep -w "ftp|anonymous" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				if [ `cat tmp_20_1.txt | grep "anonymous_enable" | grep -v "#" | grep -i -v "no$" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 차단됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat tmp_20_1.txt | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 허용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat tmp_20_1.txt | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi
rm -rf tmp_20_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-21]r 계열 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-21]r 계열 서비스 비활성화 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [21-START] >> $RESULT_FILE 2>&1
SERVICE_INETD="rsh|rlogin|rexec"
chkconfig --list | egrep $SERVICE_INETD > tmp_21_1.txt
if [ `cat tmp_21_1.txt | wc -l` -eq 0 ]
	then
		echo "★ r 계열 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [21-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-21]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_21_1.txt | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
			then
				echo "★ r 계열 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_21_1.txt >> $RESULT_FILE 2>&1
				echo [21-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-21]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ r 계열 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_21_1.txt | egrep "3:on|:.on|3:활성" >> $RESULT_FILE 2>&1
				echo [21-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-21]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_21_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-22]cron 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-22]cron 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [22-START] >> $RESULT_FILE 2>&1
ls -l /etc/ | egrep "cron.deny|cron.allow" > tmp_22_1.txt
if [ `cat tmp_22_1.txt | wc -l` -eq 0 ]
	then
		echo "★ cron.deny, cron.allow 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [22-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-22]Result : N/A >> $RESULT_FILE 2>&1
	else
		cat tmp_22_1.txt | grep "^.....-----" > tmp_22_2.txt
		if [ `diff tmp_22_1.txt tmp_22_2.txt | wc -l` -eq 0 ]
			then
				echo "★ cron 파일의 소유자 및 퍼미션(640)이 적절하게 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_22_1.txt >> $RESULT_FILE 2>&1
				echo [22-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-22]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ cron 파일의 소유자 및 퍼미션(640)이 적절하게 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_22_1.txt >> $RESULT_FILE 2>&1
				echo [22-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-22]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi	
rm -rf tmp_22_1.txt
rm -rf tmp_22_2.txt	
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-23]DoS 공격에 취약한 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-23]DoS 공격에 취약한 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [23-START] >> $RESULT_FILE 2>&1
SERVICE_INETD="echo|discard|daytime|chargen"
chkconfig --list | egrep $SERVICE_INETD > tmp_23_1.txt
if [ `cat tmp_23_1.txt | wc -l` -eq 0 ]
	then
		echo "★ DoS 공격에 취약한 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [23-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-23]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_23_1.txt | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
			then
				echo "★ DoS 공격에 취약한 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_23_1.txt >> $RESULT_FILE 2>&1
				echo [23-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-23]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ DoS 공격에 취약한 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_23_1.txt | egrep "3:on|:.on|3:활성" >> $RESULT_FILE 2>&1
				echo [23-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-23]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_23_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-24]NFS 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-24]NFS 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [24-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "nfsd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NFS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "nfsd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-25]NFS 접근통제 
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-25]NFS 접근통제   >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [25-START] >> $RESULT_FILE 2>&1

if [ `ps -ef | grep -i "nfsd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [25-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ -f /etc/exports ]
			then
				if [ `cat /etc/exports | grep -i "everyone" | grep -v "^ *#" | wc -l` -eq 0 ]
					then
						echo "★ NFS 서비스가 실행중이나 everyone 공유가 존재하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep -i "nfsd" | grep -v "grep" >> $RESULT_FILE 2>&1
						cat /etc/exports >> $RESULT_FILE 2>&1 
						echo [25-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ NFS 서비스가 실행중이고 everyone 공유가 존재함" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep -i "nfsd" | grep -v "grep" >> $RESULT_FILE 2>&1
						cat /etc/exports >> $RESULT_FILE 2>&1 
						echo [25-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-25]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ NFS 서비스가 실행중이나 /etc/exports 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep -i "nfsd" | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [25-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-25]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-26]automountd 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-26]automountd 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [26-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "automountd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ automountd 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ automountd 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "automountd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-27]RPC 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-27]RPC 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [27-START] >> $RESULT_FILE 2>&1
SERVICE_RPC="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"
if [ `chkconfig --list | egrep "$SERVICE_RPC" | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
	then
		echo "★ RPC 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [27-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-27]Result : GOOD >> $RESULT_FILE 2>&1		
	else
		echo "★ RPC 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		chkconfig --list | egrep "$SERVICE_RPC" >> $RESULT_FILE 2>&1
		echo [27-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-27]Result : VULNERABLE >> $RESULT_FILE 2>&1	
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-28]NIS, NIS+ 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-28]NIS, NIS+ 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [28-START] >> $RESULT_FILE 2>&1
SERVICE_NIS="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"
if [ `ps -ef | egrep $SERVICE_NIS | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NIS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NIS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep $SERVICE_NIS | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-29]tftp, talk 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-29]tftp, talk 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [29-START] >> $RESULT_FILE 2>&1
if [ `chkconfig --list | egrep "tftp|talk" | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
	then
		echo "★ tftp, talk 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [29-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-29]Result : GOOD >> $RESULT_FILE 2>&1		
	else
		echo "★ tftp, talk 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		chkconfig --list | egrep "tftp|talk" >> $RESULT_FILE 2>&1
		echo [29-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-29]Result : VULNERABLE >> $RESULT_FILE 2>&1	
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-30]Sendmail 버전 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-30]Sendmail 버전 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [30-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [30-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [30-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-30]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_30_1.txt \;			
				if [ `cat tmp_30_1.txt | grep -v '^ *#' | grep DZ | egrep "8.15" | wc -l` -eq 0 ]
					then
						echo "★ 취약한 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat tmp_30_1.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ 취약하지 않은 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat tmp_30_1.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_30_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-31]스팸 메일 릴레이 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-31]스팸 메일 릴레이 제한 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [31-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [31-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-31]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [31-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-31]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_31_1.txt \;
				if [ `cat tmp_31_1.txt | grep -v "^ *#" | grep "R$\*" | grep -i "Relaying denied" | wc -l ` -gt 0 ]
					then
						echo "★ 스팸 메일 릴레이 제한 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat tmp_31_1.txt | grep -v "^ *#" | grep "R$\*" | grep -i "Relaying denied" >> $RESULT_FILE 2>&1
						echo [31-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-31]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 스팸 메일 릴레이 제한 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat tmp_31_1.txt | grep "R$\*" | grep -i "Relaying denied" >> $RESULT_FILE 2>&1
						echo [31-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-31]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_31_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-32]일반사용자의 Sendmail 실행 방지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-32]일반사용자의 Sendmail 실행 방지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [32-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [32-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-32]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [32-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-32]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_32_1.txt \;
				if [ `cat tmp_32_1.txt | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "#" | wc -l` -gt 0 ]
					then
						echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat tmp_32_1.txt | grep -i "O PrivacyOptions" | grep -i "restrictqrun" >> $RESULT_FILE 2>&1
						echo [32-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-32]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat tmp_32_1.txt | grep -i "O PrivacyOptions" >> $RESULT_FILE 2>&1
						echo [32-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-32]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_32_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-33]DNS 보안 버전 패치
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-33]DNS 보안 버전 패치 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [33-START] >> $RESULT_FILE 2>&1
if [ `netstat -anp | awk '{print $4}' | grep ":53$" | wc -l` -eq 0 ]
	then
		echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [33-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-33]Result : GOOD >> $RESULT_FILE 2>&1
	else
		named -v > /dev/null
		if [ $? -eq 0 ]
			then
				echo "★ DNS 서비스가 실행중이며 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				named -v >> $RESULT_FILE 2>&1
				echo [33-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ -f /usr/sbin/named ]
					then
						echo "★ DNS 서비스가 실행중임 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						/usr/sbin/named -v >> $RESULT_FILE 2>&1
						echo [33-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
					else
						if [ -f /usr/sbin/named9 ]
							then
								echo "★ DNS 서비스가 실행중임 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
								echo "[현황]" >> $RESULT_FILE 2>&1
								/usr/sbin/named9 -v >> $RESULT_FILE 2>&1
								echo [33-END] >> $RESULT_FILE 2>&1
								echo >> $RESULT_FILE 2>&1
								echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
							else
								echo "★ DNS 서비스가 실행중이나 실행 데몬을 찾을 수 없음" >> $RESULT_FILE 2>&1
								echo [33-END] >> $RESULT_FILE 2>&1
								echo >> $RESULT_FILE 2>&1
								echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
						fi
				fi
		fi
fi		
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-34]DNS ZoneTransfer 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-34]DNS ZoneTransfer 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [34-START] >> $RESULT_FILE 2>&1
if [ `netstat -anp | awk '{print $4}' | grep ":53$" | wc -l` -eq 0 ]
	then
		echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [34-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-34]Result : GOOD >> $RESULT_FILE 2>&1
	else
		cat /etc/named.conf /etc/named.rfc1912.zones /etc/named.boot > tmp_34_1.txt 2> /dev/null
		if [ `cat tmp_34_1.txt | wc -l` -eq 0 ]
			then
				echo "★ DNS 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1
				echo [34-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-34]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ `cat tmp_34_1.txt | grep "allow-transfer" | grep -v "#" | wc -l` -eq 0 ]
					then
						echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1						
						echo [34-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-34]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1
						cat tmp_34_1.txt | grep "allow-transfer" | grep -v "#" >> $RESULT_FILE 2>&1
						echo [34-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-34]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_34_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-42]최신 보안패치 및 벤더 권고사항 적용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-42]최신 보안패치 및 벤더 권고사항 적용  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
# echo [42-START] >> $RESULT_FILE 2>&1
# echo "★ 인터뷰 점검 항목" >> $RESULT_FILE 2>&1
# echo [42-END] >> $RESULT_FILE 2>&1
# echo >> $RESULT_FILE 2>&1
# echo [U-42]Result : MANUAL >> $RESULT_FILE 2>&1
echo [42-START] >> $RESULT_FILE 2>&1
echo "★ 아래 현황을 기반으로 수동분석" >> $RESULT_FILE 2>&1
echo "[현황]" >> $RESULT_FILE 2>&1
echo "1. OpenSSL Version" >> $RESULT_FILE 2>&1
openssl version >> $RESULT_FILE 2>&1
echo "2. Bash Shell Version" >> $RESULT_FILE 2>&1
bash --version | grep "bash" >> $RESULT_FILE 2>&1
rpm -qa | grep bash >> $RESULT_FILE 2>&1
echo "2.1 Bash 취약점 테스트(벤더사 제공)" >> $RESULT_FILE 2>&1
env x='() { :;}; echo vulnerable' bash -c "echo this is a test" >> $RESULT_FILE 2>&1
echo [42-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-42]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-43]로그의 정기적 검토 및 보고
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-43]로그의 정기적 검토 및 보고  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [43-START] >> $RESULT_FILE 2>&1
echo "★ 인터뷰 점검 항목" >> $RESULT_FILE 2>&1
echo [43-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-43]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-44]root 이외의 UID가 '0' 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-44]root 이외의 UID가 '0' 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [44-START] >> $RESULT_FILE 2>&1
if [ `awk -F: '$3==0 {print $0}' /etc/passwd | grep -v 'root' | wc -l` -eq 0 ]
	then
		echo "★ root 이외의 UID가 '0'인 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-5]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ root 이외의 UID가 '0'인 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-44]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-45]root 계정 su 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-45]root 계정 su 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [45-START] >> $RESULT_FILE 2>&1
if [ -f /etc/pam.d/su ]
	then
		if [ `grep "wheel.so" /etc/pam.d/su | grep -v "trust" | grep -v "#" | grep "use_uid" | wc -l` -eq 0 ]
			then
				echo "★ su 명령 사용이 특정 그룹으로 제한되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep "wheel.so" /etc/pam.d/su >> $RESULT_FILE 2>&1
				echo [45-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-45]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ su 명령 사용이 특정 그룹으로 제한되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep "wheel.so" /etc/pam.d/su >> $RESULT_FILE 2>&1
				echo [45-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-45]Result : GOOD >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/pam.d/su 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [45-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-45]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-46]패스워드 최소 길이 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-46]패스워드 최소 길이 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [46-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "system-auth" | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [46-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-46]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTH=`find /etc -name "system-auth"`
		if [ `grep -i "password" /etc/pam.d/system-auth | grep "minlen" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최소 길이 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [46-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-46]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep -i "password" /etc/pam.d/system-auth | awk -F "minlen=" '{print $2}' | awk '{print $1}'` -gt 46 ]
					then
						echo "★ 패스워드 최소 길이 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
						echo [46-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-46]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최소 길이 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
						echo [46-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-46]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-47]패스워드 최대 사용 기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-47]패스워드 최대 사용 기간 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [47-START] >> $RESULT_FILE 2>&1
touch tmp_47_3.txt
cat /etc/passwd | egrep -v 'false|nologin|null|halt|sync|shutdown' > tmp_47_1.txt
cat tmp_47_1.txt | awk -F: '{print $1}' > tmp_47_2.txt
for i in `cat tmp_47_2.txt`; do 
echo user: "              $i" >> tmp_47_3.txt
chage -l $i | grep 'Last' >> tmp_47_3.txt; done
if [ -f /etc/login.defs ]
	then
		if [ `grep "PASS_MAX_DAYS" /etc/login.defs | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최대 사용 기간 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [47-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep "PASS_MAX_DAYS" /etc/login.defs | grep -v "#" | awk '{print $2}'` -gt 90 ]
					then
						echo "★ 패스워드 최대 사용 기간 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MAX_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo "1. 계정별 패스워드 최근 변경일" >> $RESULT_FILE 2>&1
						cat tmp_47_3.txt >> $RESULT_FILE 2>&1
						echo [47-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최대 사용 기간 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MAX_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo "1. 계정별 패스워드 최근 변경일" >> $RESULT_FILE 2>&1
						cat tmp_47_3.txt >> $RESULT_FILE 2>&1
						echo [47-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1					
						echo [U-47]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
	else
		echo "★ /etc/login.defs 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm tmp_47_1.txt
rm tmp_47_2.txt
rm tmp_47_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-48]패스워드 최소 사용기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-48]패스워드 최소 사용기간 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [48-START] >> $RESULT_FILE 2>&1
if [ -f /etc/login.defs ]
	then
		if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [48-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-48]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | awk '{print $2}'` -eq 1 ]
					then
						echo "★ 패스워드 최소 사용 기간 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1				
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [48-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1	
						echo [U-48]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [48-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-48]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
	else
		echo "★ /etc/login.defs 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [48-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-48]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-49]불필요한 계정 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-49]불필요한 계정 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [49-START] >> $RESULT_FILE 2>&1
touch tmp_49_3.txt
cat /etc/passwd | egrep -v 'false|nologin|null|halt|sync|shutdown|rpm|new' > tmp_49_1.txt
cat tmp_49_1.txt | awk -F: '{print $1}' > tmp_49_2.txt
for i in `cat tmp_49_2.txt`; do 
lastlog -u $i | grep $i >> tmp_49_3.txt; done
if [ `awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | grep -v "nfsnobody" | wc -l` -eq 0 ]
	then
		echo "★ UID 500 이상 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat tmp_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ UID 500 이상 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | grep -v "nfsnobody" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat tmp_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm tmp_49_1.txt
rm tmp_49_2.txt
rm tmp_49_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-50]관리자 그룹에 최소한의 계정 포함
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-50]관리자 그룹에 최소한의 계정 포함  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [50-START] >> $RESULT_FILE 2>&1
grep "^root" /etc/group | awk -F ":" '{print $4}' | sed s/,/\\n/g | grep -v "^root$" | wc -w > tmp_50.txt
if [ `cat tmp_50.txt` -eq 0 ]
	then
		echo "★ 관리자 그룹에 root 이외의 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 관리자 그룹에 root 이외의 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf tmp_50.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-51]계정이 존재하지 않는 GID 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-51]계정이 존재하지 않는 GID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [51-START] >> $RESULT_FILE 2>&1
awk -F : '$4 == null {print $0}' /etc/group | awk -F : '$3 >= 500 {print $0}' > tmp_group.txt
awk -F : '{print $4}' /etc/passwd > tmp_passwd.txt
for TGID in `cat tmp_passwd.txt`
	do
		grep -v ":$TGID:" tmp_group.txt > tmp.txt
		cat tmp.txt > tmp_group.txt
done
if [ `cat tmp_group.txt | wc -w` -eq 0 ]
	then
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		cat tmp_group.txt >> $RESULT_FILE 2>&1 
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_group.txt
rm -rf tmp_passwd.txt
rm -rf tmp.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-52]동일한 UID 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-52]동일한 UID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [52-START] >> $RESULT_FILE 2>&1
awk -F : '{print $3}' /etc/passwd > tmp_passwd.txt
if [ `cat tmp_passwd.txt | sort | uniq -d | wc -l` -eq 0 ]
	then
		echo "★ 중복된 UID가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [52-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-52]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 중복된 UID가 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		DUID=`cat tmp_passwd.txt | sort | uniq -d`
		grep "x:$DUID:" /etc/passwd >> $RESULT_FILE 2>&1
		echo [52-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-52]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_passwd.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-53]사용자 shell 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-53]사용자 shell 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [53-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  awk -F: '{print $7}'| egrep -v 'false|nologin|null|halt|sync|shutdown' | wc -l` -eq 0 ]
	then
		echo "★ 점검 대상 시스템 계정에 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 점검 대상 시스템 계정에 쉘이 부여됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-54]Session Timeout 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-54]Session Timeout 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [54-START] >> $RESULT_FILE 2>&1
if [ `echo $TMOUT | wc -w` -eq 0 ]
	then
		echo "★ 세션 타임아웃이 설정되지 않음" >> $RESULT_FILE 2>&1
		echo [54-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-54]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		if [ `echo $TMOUT` -gt 600 ]
			then
				echo "★ 세션 타임아웃이 설정되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				echo "TMOUT : `echo $TMOUT`" >> $RESULT_FILE 2>&1
				echo [54-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-54]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 세션 타임아웃이 정책에 맞게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				echo "TMOUT : `echo $TMOUT`" >> $RESULT_FILE 2>&1
				echo [54-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-54]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-55]hosts.lpd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-55]hosts.lpd 파일 소유자 및 권한 설정 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [55-START] >> $RESULT_FILE 2>&1
if [ -f /etc/hosts.lpd ]
	then
		if [ `ls -l /etc/hosts.lpd | grep "^........-." | awk '$3=="root"' | wc -l` -eq 0 ]
			then
				echo "★ /etc/hosts.lpd 파일의 소유자 및 퍼미션(o-w)이 적절하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/hosts.lpd >> $RESULT_FILE 2>&1
				echo [55-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-55]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/hosts.lpd 파일의 소유자 및 퍼미션(o-w)이 적절하게 설정되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/hosts.lpd >> $RESULT_FILE 2>&1
				echo [55-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-55]Result : GOOD >> $RESULT_FILE 2>&1
		fi
	else
		echo "★ /etc/hosts.lpd 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [55-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-55]Result : GOOD >> $RESULT_FILE 2>&1
fi	
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-56]NIS 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-56]NIS 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [56-START] >> $RESULT_FILE 2>&1
NISSERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
if [ `ps -ef | egrep $NISSERVICE | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NIS, NIS+ 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [56-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-56]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NIS, NIS+ 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep $SERVICE | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [56-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-56]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-57]UMASK 설정 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-57]UMASK 설정 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [57-START] >> $RESULT_FILE 2>&1
if [ `umask` -eq 0022 ]
	then
		echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1		
		echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
		echo [57-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `umask` -eq 0027 ]
			then
				echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [57-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ UMASK 값이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [57-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-57]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-58]홈디렉토리 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-58]홈디렉토리 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [58-START] >> $RESULT_FILE 2>&1
ls -l /home/ | grep -v "+found" | sed -n '2,$p' > tmp_58_1.txt
cat tmp_58_1.txt | grep -v "^........w." > tmp_58_2.txt
if [ `cat tmp_58_1.txt | wc -l` -eq 0 ]
	then
		echo "★ 사용자 홈디렉토리가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [58-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-58]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `diff tmp_58_1.txt tmp_58_2.txt | wc -l` -eq 0 ]
			then
				echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_58_1.txt >> $RESULT_FILE 2>&1
				echo [58-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-58]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_58_1.txt | grep "^........w." >> $RESULT_FILE 2>&1
				echo [58-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-58]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_58_1.txt
rm -rf tmp_58_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-59]홈디렉토리로 지정한 디렉토리의 존재 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-59]홈디렉토리로 지정한 디렉토리의 존재 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [59-START] >> $RESULT_FILE 2>&1
cat /etc/passwd | awk -F: '$3>=500 {print $0}' > tmp_59_1.txt
cat tmp_59_1.txt | awk -F: '{print $6}' > tmp_59_2.txt
touch tmp_59_3.txt
for i in `cat tmp_59_2.txt`
	do
		if [ -d $i ]; then echo $i >> tmp_59_3.txt; else true; fi
done
if [ `diff tmp_59_2.txt tmp_59_3.txt | wc -l` -eq 0 ]
	then
		echo "★ 홈디렉토리가 존재하지 않는 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [59-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-59]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 홈디렉토리가 존재하지 않는 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		diff tmp_59_2.txt tmp_59_3.txt | grep "<" | awk '{print $2}' > tmp_59_4.txt
		for i in `cat tmp_59_4.txt`
			do
				cat /etc/passwd | grep $i | awk -F: '{print "계정  "$1"  의 홈디렉토리  "$6"  가 존재하지 않음"}' >> $RESULT_FILE 2>&1
		done
		echo [59-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-59]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_59_1.txt
rm -rf tmp_59_2.txt
rm -rf tmp_59_3.txt
rm -rf tmp_59_4.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-60]숨겨진 파일 및 디렉토리 검색 및 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-60]숨겨진 파일 및 디렉토리 검색 및 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [60-START] >> $RESULT_FILE 2>&1
find /tmp/ | grep "/\." > tmp_60_1.txt
if [ `cat tmp_60_1.txt | wc -l` -eq 0 ]
	then
		echo "★ /tmp 디렉토리에 숨김 속성 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-60]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ /tmp 디렉토리에 숨김 속성 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_60_1.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_60_1.txt | wc -l >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-60]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_60_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-61]ssh 원격접속 허용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-61]ssh 원격접속 허용  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [61-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "sshd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SSH 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-61]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		echo "★ SSH 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "sshd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-61]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-62]ftp 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-62]ftp 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [62-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [62-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-62]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ FTP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "ftpd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [62-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-62]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-63]ftp 계정 shell 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-63]ftp 계정 shell 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [63-START] >> $RESULT_FILE 2>&1
cat /etc/passwd | grep -w "^ftp" > tmp_63_1.txt
if [ `cat tmp_63_1.txt | wc -l` -eq 0 ]
	then
		echo "★ /etc/passwd 파일에 'ftp' 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [63-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-63]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_63_1.txt | awk -F: '{print $7}' | egrep -v "false|nologin|null|halt|sync|shutdown" | wc -l` -eq 0 ]
			then
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_63_1.txt >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_63_1.txt >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_63_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-64]Ftpusers 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-64]Ftpusers 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [64-START] >> $RESULT_FILE 2>&1
find /etc -name "ftpusers" -exec ls -l {} \; > tmp_64_1.txt
if [ `cat tmp_64_1.txt | wc -l` -eq 0 ]
	then
		echo "★ ftpusers 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [64-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-64]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_64_1.txt | grep "^.....-----" | awk '$3=="root"' | wc -l` -eq 0 ]
			then
				echo "★ ftpusers 파일의 소유자 및 퍼미션이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_64_1.txt >> $RESULT_FILE 2>&1
				echo [64-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-64]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ ftpusers 파일의 소유자 및 퍼미션이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_64_1.txt >> $RESULT_FILE 2>&1
				echo [64-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-64]Result : GOOD >> $RESULT_FILE 2>&1				
		fi
fi
rm -rf cat tmp_64_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-65]Ftpusers 파일 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-65]Ftpusers 파일 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [65-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [65-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "ftpusers" -exec ls -l {} \; > tmp_65_1.txt
		if [ `cat tmp_65_1.txt | wc -l` -eq 0 ]
			then
				echo "★ ftpusers 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [65-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
			else
				find /etc -name "ftpusers" -exec cat {} \; > tmp_65_2.txt
				if [ `cat tmp_65_2.txt | grep "root" | grep -v "^ *#" | wc -l` -gt 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재함" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_65_1.txt >> $RESULT_FILE 2>&1
						cat tmp_65_2.txt >> $RESULT_FILE 2>&1
						echo [65-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_65_1.txt >> $RESULT_FILE 2>&1
						cat tmp_65_2.txt >> $RESULT_FILE 2>&1
						echo [65-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-65]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi		
rm -rf tmp_65_1.txt
rm -rf tmp_65_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-66]at 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-66]at 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [66-START] >> $RESULT_FILE 2>&1
ls -l /etc/ | egrep "at.deny|at.allow" > tmp_66_1.txt
if [ `cat tmp_66_1.txt | wc -l` -eq 0 ]
	then
		echo "★ at.deny, at.allow 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [66-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-66]Result : GOOD >> $RESULT_FILE 2>&1
	else
		cat tmp_66_1.txt | grep "^.....-----" | awk '$3=="root"' > tmp_66_2.txt
		if [ `diff tmp_66_1.txt tmp_66_2.txt | wc -l` -eq 0 ]
			then
				echo "★ at 파일의 소유자 및 퍼미션(640)이 적절하게 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_66_1.txt >> $RESULT_FILE 2>&1
				echo [66-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-66]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ cron 파일의 소유자 및 퍼미션(640)이 적절하게 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_66_1.txt >> $RESULT_FILE 2>&1
				echo [66-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-66]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf cat tmp_66_1.txt
rm -rf cat tmp_66_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-67]SNMP 서비스 구동 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-67]SNMP 서비스 구동 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [67-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [67-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-67]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ SNMP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "snmpd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [67-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-67]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-68]SNMP 서비스 커뮤니티스트링의 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-68]SNMP 서비스 커뮤니티스트링의 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [68-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [68-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-68]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "snmpd.conf" -exec cat {} \; > tmp_68_1.txt
		if [ `cat tmp_68_1.txt | wc -l` -gt 0 ]
			then
				if [ `cat tmp_68_1.txt | grep "public" | grep -v "^ *#" | wc -l` -eq 0 ]
					then
						echo "★ SNMP Community String이 임의의 값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_68_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [68-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-68]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ SNMP Community String이 기본값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_68_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [68-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-68]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ SNMP 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : MANUAL >> $RESULT_FILE 2>&1
		fi						
fi
rm -rf tmp_68_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-69]로그온 시 경고 메시지 제공
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-69]로그온 시 경고 메시지 제공  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [69-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/issue.net | wc -l` -gt 2 ]
	then
		if [ `cat /etc/motd | wc -l` -gt 0 ]
			then
				echo "★ /etc/issue.net, /etc/motd 파일에 경고 메시지가 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				echo "1) /etc/issue.net 파일 내용" >> $RESULT_FILE 2>&1
				cat /etc/issue.net >> $RESULT_FILE 2>&1
				echo "2) /etc/motd 파일 내용" >> $RESULT_FILE 2>&1
				cat /etc/motd >> $RESULT_FILE 2>&1
				echo [69-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-69]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/motd 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [69-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		if [ `cat /etc/motd | wc -l` -gt 0 ]
			then
				echo "★ /etc/issue.net 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [69-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/issue.net, /etc/motd 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [69-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-70]NFS 설정 파일 접근 권한 
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-70]NFS 설정 파일 접근 권한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [70-START] >> $RESULT_FILE 2>&1
if [ -f /etc/exports ]
	then
		if [ `ls -l /etc/exports | grep "^.....--.--" | wc -l` -eq 0 ]
			then
				echo "★ /etc/exports 파일의 퍼미션(644)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/exports >> $RESULT_FILE 2>&1
				echo [70-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-70]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/exports 파일의 퍼미션(644)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -l /etc/exports >> $RESULT_FILE 2>&1
				echo [70-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-70]Result : GOOD >> $RESULT_FILE 2>&1
		fi	
	else
		echo "★ /etc/exports 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [70-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-70]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-71]expn, vrfy 명령어 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-71]expn, vrfy 명령어 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [71-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [71-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-71]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [71-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-71]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_71.txt \;			
				cat tmp_71.txt | grep -i "O PrivacyOptions" > tmp_71_1.txt
				if [ `cat tmp_71_1.txt | grep -v "^ *#" | grep "noexpn" | grep "novrfy" | wc -l` -eq 0 ]
					then
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_71_1.txt >> $RESULT_FILE 2>&1
						echo [71-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-71]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_71_1.txt >> $RESULT_FILE 2>&1
						echo [71-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-71]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_71.txt
rm -rf tmp_71_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-73]정책에 따른 시스템 로깅 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-73]정책에 따른 시스템 로깅 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [73-START] >> $RESULT_FILE 2>&1
if [ -f /etc/syslog.conf ]
	then
		cat /etc/syslog.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_73_1.txt
	else
		if [ -f /etc/rsyslog.conf ]
			then
				cat /etc/rsyslog.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_73_1.txt
			else
				echo "★ (r)syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [73-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-73]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
fi
if [ `cat tmp_73_1.txt | egrep -w "cron.\*|authpriv.\*|\*.info" | wc -l` -eq 3 ]
	then
		echo "★ (r)syslog.conf 설정이 적절하게 설정됨 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_73_1.txt >> $RESULT_FILE 2>&1
		echo [73-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-73]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 아래 현황을 기반으로 수동분석 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_73_1.txt >> $RESULT_FILE 2>&1
		echo [73-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-73]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf tmp_73_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-74]정책에 따른 시스템 로깅 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-74]정책에 따른 시스템 로깅 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [74-START] >> $RESULT_FILE 2>&1
if [ -f /etc/rsyslog.d/50-default.conf ]
	then
		cat /etc/rsyslog.d/50-default.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_74_1.txt
	else
		if [ -f /etc/rsyslog.d/50-default.conf ]
			then
				cat /etc/rsyslog.d/50-default.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_74_1.txt
			else
				echo "★ (r)syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [74-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-74]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
fi
if [ `cat tmp_73_1.txt | egrep -w "cron.\*|authpriv.\*|\*.info" | wc -l` -eq 3 ]
	then
		echo "★ (r)syslog.conf 설정이 적절하게 설정됨 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_74_1.txt >> $RESULT_FILE 2>&1
		echo [74-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-74]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 아래 현황을 기반으로 수동분석 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_74_1.txt >> $RESULT_FILE 2>&1
		echo [74-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-74]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf tmp_74_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Version ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
uname -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/issue >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ ping test ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ping -c 3 www.google.com >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Interface ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ifconfig -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/passwd ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/passwd  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/shadow ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/shadow  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Socket ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
netstat -anp | head -200 >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Daemon ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "1) ps -ef" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ps -ef >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "2) chkconfig --list" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
chkconfig --list >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Iptables]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
iptables -L >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ TCP Wrapper]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "1) /etc/hosts.deny" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/hosts.deny >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "2) /etc/hosts.allow" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/hosts.allow >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Ubuntu Log]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat  /etc/rsyslog.d/50-default.conf >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ PW setting]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "1) common-password" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat  /etc/pam.d/common-password  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "2) common-auth" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat  /etc/pam.d/common-auth  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "3) pwquailty.conf" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/security/pwquailty.conf >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "4) password-auth" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/pam.d/password-auth >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo  "5) system-auth" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/pam.d/system-auth >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo ""
echo "==============================  END  ==============================" 

#Archive 생성
tar cf Linux\(A\)@@`hostname`@@$IP.tar Linux@@`hostname`@@$IP.txt Apache@@`hostname`@@$IP.txt
rm -rf Linux@@`hostname`@@$IP.txt
rm -rf Apache@@`hostname`@@$IP.txt

exit;;

esac
