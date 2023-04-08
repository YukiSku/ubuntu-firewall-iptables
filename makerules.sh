#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin

###########################################################################################
# IPTABLESのルールを作成します。cidr.txtがダウンロードされていることが前提です。
#   -A  チェーンの終わりにルールを追記する。
#   -I  値として指定した位置にルールを挿入する。指定無しならチェーンの最上部にルールを置く。
###########################################################################################

echo "Refreshing rules of IPTABLES.........."

# IPアドレスリスト取得。DLは別スクリプトで実行。
IP_LIST=/root/COUNTRY_CODE/cidr.txt

if [ -z "$IP_LIST" ]; then
    echo "Error: Can't find country_code_list. Refreshing was canceled."
    echo "Please create/execute /etc/cron.monthly/dl_iplist before."
    exit 1
fi

# 内部ネットワークアドレス設定
LOCALNET=192.168.0.0/16

# 設定ファイルの場所
IPTABLES_CONFIG=/etc/iptables/rules.v4

# 現在の設定ファイルを消去
rm -f $IPTABLES_CONFIG

# デフォルトルール(以降のルールにマッチしなかった場合に適用するルール)設定
echo "*filter" >> $IPTABLES_CONFIG
echo ":INPUT DROP [0:0]" >> $IPTABLES_CONFIG       # 受信はすべて破棄
echo ":FORWARD DROP [0:0]" >> $IPTABLES_CONFIG     # 通過はすべて破棄
echo ":OUTPUT ACCEPT [0:0]" >> $IPTABLES_CONFIG    # 送信はすべて許可
echo ":ACCEPT_COUNTRY - [0:0]" >> $IPTABLES_CONFIG # 指定した国からのアクセスを許可
echo ":DROP_COUNTRY - [0:0]" >> $IPTABLES_CONFIG   # 指定した国からのアクセスを破棄
echo ":LOG_PINGDEATH - [0:0]" >> $IPTABLES_CONFIG  # Ping of Death攻撃はログを記録して破棄

# 自ホストからのアクセスをすべて許可
echo "-A INPUT -i lo -j ACCEPT" >> $IPTABLES_CONFIG

# 内部からのアクセスをすべて許可
echo "-A INPUT -s $LOCALNET -j ACCEPT" >> $IPTABLES_CONFIG

# 内部から行ったアクセスに対する外部からの返答アクセスを許可
echo "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT" >> $IPTABLES_CONFIG

# フラグメント化されたパケットはログを記録して破棄
echo "-A INPUT -f -j LOG --log-prefix \"[IPTABLES FRAGMENT] : \"" >> $IPTABLES_CONFIG
echo "-A INPUT -f -j DROP" >> $IPTABLES_CONFIG

# 外部とのNetBIOS関連のアクセスはログを記録せずに破棄
# 不要ログ記録防止
echo "-A INPUT ! -s $LOCALNET -p tcp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG
echo "-A INPUT ! -s $LOCALNET -p udp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG
echo "-A OUTPUT ! -d $LOCALNET -p tcp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG
echo "-A OUTPUT ! -d $LOCALNET -p udp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG

# 1秒間に4回を超えるpingはログを記録して破棄
# Ping of Death攻撃対策
echo "-A LOG_PINGDEATH -m limit --limit 1/s --limit-burst 4 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A LOG_PINGDEATH -j LOG --log-prefix \"[IPTABLES PINGDEATH] : \"" >> $IPTABLES_CONFIG
echo "-A LOG_PINGDEATH -j DROP" >> $IPTABLES_CONFIG
echo "-A INPUT -p icmp --icmp-type echo-request -j LOG_PINGDEATH" >> $IPTABLES_CONFIG

# 全ホスト(ブロードキャストアドレス、マルチキャストアドレス)宛パケットはログを記録せずに破棄
# ※不要ログ記録防止
echo "-A INPUT -d 255.255.255.255 -j DROP" >> $IPTABLES_CONFIG
echo "-A INPUT -d 224.0.0.1 -j DROP" >> $IPTABLES_CONFIG

# 113番ポート(IDENT)へのアクセスには拒否応答
# ※メールサーバ等のレスポンス低下防止
echo "-A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset" >> $IPTABLES_CONFIG

# ACCEPT_COUNTRY_MAKE関数定義
# 指定された国のIPアドレスからのアクセスを許可するユーザ定義チェイン作成
ACCEPT_COUNTRY_MAKE(){
    for addr in `cat $IP_LIST |grep ^$1|awk '{print $2}'`
    do
        echo "-A ACCEPT_COUNTRY -s $addr -j ACCEPT" >> $IPTABLES_CONFIG
    done
}

# DROP_COUNTRY_MAKE関数定義
# 指定された国のIPアドレスからのアクセスを破棄するユーザ定義チェイン作成
DROP_COUNTRY_MAKE(){
    for addr in `cat $IP_LIST |grep ^$1|awk '{print $2}'`
    do
        echo "-A DROP_COUNTRY -s $addr -m limit --limit 1/s -j LOG --log-prefix \"[IPTABLES DENY_COUNTRY] : \"" >> $IPTABLES_CONFIG
        echo "-A DROP_COUNTRY -s $addr -j DROP" >> $IPTABLES_CONFIG
    done
}

# 日本からのアクセスを許可するユーザ定義チェインACCEPT_COUNTRY作成
ACCEPT_COUNTRY_MAKE JP
# 以降,日本からのみアクセスを許可したい場合はACCEPTのかわりにACCEPT_COUNTRYを指定する

# 不正アクセスの多い海外からのアクセスをログを記録して破棄
DROP_COUNTRY_MAKE AE
DROP_COUNTRY_MAKE AF
DROP_COUNTRY_MAKE AU
DROP_COUNTRY_MAKE AR
DROP_COUNTRY_MAKE BA
DROP_COUNTRY_MAKE BB
DROP_COUNTRY_MAKE BD
DROP_COUNTRY_MAKE BE
DROP_COUNTRY_MAKE BG
DROP_COUNTRY_MAKE BN
DROP_COUNTRY_MAKE BR
DROP_COUNTRY_MAKE BW
DROP_COUNTRY_MAKE BY
DROP_COUNTRY_MAKE BZ
DROP_COUNTRY_MAKE CI
DROP_COUNTRY_MAKE CL
DROP_COUNTRY_MAKE CN
DROP_COUNTRY_MAKE CO
DROP_COUNTRY_MAKE CV
DROP_COUNTRY_MAKE CZ
DROP_COUNTRY_MAKE DE
DROP_COUNTRY_MAKE DO
DROP_COUNTRY_MAKE EG
DROP_COUNTRY_MAKE ES
DROP_COUNTRY_MAKE ET
DROP_COUNTRY_MAKE FR
DROP_COUNTRY_MAKE GU
DROP_COUNTRY_MAKE GH
DROP_COUNTRY_MAKE HK
DROP_COUNTRY_MAKE ID
DROP_COUNTRY_MAKE IL
DROP_COUNTRY_MAKE IN
DROP_COUNTRY_MAKE IR
DROP_COUNTRY_MAKE IT
DROP_COUNTRY_MAKE JO
DROP_COUNTRY_MAKE KE
DROP_COUNTRY_MAKE KH
DROP_COUNTRY_MAKE KP
DROP_COUNTRY_MAKE KR
DROP_COUNTRY_MAKE LT
DROP_COUNTRY_MAKE LV
DROP_COUNTRY_MAKE MD
DROP_COUNTRY_MAKE ML
DROP_COUNTRY_MAKE MN
DROP_COUNTRY_MAKE MU
DROP_COUNTRY_MAKE MX
DROP_COUNTRY_MAKE MY
DROP_COUNTRY_MAKE NG
DROP_COUNTRY_MAKE NL
DROP_COUNTRY_MAKE NP
DROP_COUNTRY_MAKE NZ
DROP_COUNTRY_MAKE OM
DROP_COUNTRY_MAKE PA
DROP_COUNTRY_MAKE PE
DROP_COUNTRY_MAKE PH
DROP_COUNTRY_MAKE PK
DROP_COUNTRY_MAKE PL
DROP_COUNTRY_MAKE RO
DROP_COUNTRY_MAKE RS
DROP_COUNTRY_MAKE RU
DROP_COUNTRY_MAKE SD
DROP_COUNTRY_MAKE SG
DROP_COUNTRY_MAKE TH
DROP_COUNTRY_MAKE TN
DROP_COUNTRY_MAKE TR
DROP_COUNTRY_MAKE TW
DROP_COUNTRY_MAKE UA
DROP_COUNTRY_MAKE UG
DROP_COUNTRY_MAKE UY
DROP_COUNTRY_MAKE VN
DROP_COUNTRY_MAKE ZA
DROP_COUNTRY_MAKE ZW

### ASNから調査したIP Range。アメリカに設置されたサーバー等。
## Ucloud VPS
# Chinese company in US. Their servers in US have attacked repeatedly with US_IP.
if [ -s /root/COUNTRY_CODE/ucloud.txt ]; then
    for ip in `cat /root/COUNTRY_CODE/ucloud.txt | awk '{print $1}' | grep '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.'`
    do
        if [ -n $ip ]; then
            echo "-A DROP_COUNTRY -s $ip -j DROP" >> $IPTABLES_CONFIG
        fi
    done
fi

## Zwiebelfreunde Cloud sevice at Germany and IPs of servers in US.
# They've repeatedly tried to auth pop3.
echo "-A DROP_COUNTRY -s 185.220.101.0/24 -j DROP" >> $IPTABLES_CONFIG

## Censys.io from US. -- AS398324
# They're white hackers, but I don't allow them investigating.
echo "-A DROP_COUNTRY -s 162.142.125.0/24 -j DROP" >> $IPTABLES_CONFIG
echo "-A DROP_COUNTRY -s 167.94.138.0/24 -j DROP" >> $IPTABLES_CONFIG

## Hurricane Electric
#if [ -s /root/COUNTRY_CODE/hurricaneelectricllc.txt ]; then
#    for ip in `cat /root/COUNTRY_CODE/hurricaneelectricllc.txt | awk '{print $1}' | grep '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.'`
#    do
#        if [ -n $ip ]; then
#            echo "-A DROP_COUNTRY -s $ip -j DROP" >> $IPTABLES_CONFIG
#        fi
#    done
#fi

## degitalocean
#if [ -s /root/COUNTRY_CODE/degitalocean.txt ]; then
#    for ip in `cat /root/COUNTRY_CODE/degitalocean.txt | awk '{print $1}' | grep '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.'`
#    do
#        if [ -n $ip ]; then
#            echo "-A DROP_COUNTRY -s $ip -j DROP" >> $IPTABLES_CONFIG
#        fi
#    done
#fi

# INPUTにチェインを組み込む
echo "-I INPUT -j DROP_COUNTRY" >> $IPTABLES_CONFIG

#----------------------------------------------------------#
# 各種サービスを公開する場合の設定(ここから)               #
#----------------------------------------------------------#

# 外部からのTCP/UDP53番ポート(DNS)へのアクセスを許可
# 外部向けDNSサーバーを運用する場合のみ
#echo "-A INPUT -p tcp --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG
#echo "-A INPUT -p udp --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG

# 外部からのTCP80番ポート(HTTP)へのアクセスを許可
# 外部からのTCP443番ポート(HTTPS)へのアクセスを許可
# Let's encryptの証明書更新のためには80番ポートを海外からアクセス可能にする必要があります。
echo "-A INPUT -p tcp --dport 80 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp --dport 443 -j ACCEPT" >> $IPTABLES_CONFIG

# 80番ポート(http)に対して1秒に5回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 80 -m hashlimit --hashlimit-name t_http --hashlimit 1/s --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-htable-expire 900000 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW --dport 80 -j DROP" >> $IPTABLES_CONFIG

# 443番ポート(https)に対して1秒に5回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 443 -m hashlimit --hashlimit-name t_https --hashlimit 1/s --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-htable-expire 900000 -j ACCEPT" >> $IPTABLES_CONFIG
echo -A INPUT -p tcp -m state --state NEW --dport 443 -j DROP >> $IPTABLES_CONFIG

# 外部からのTCP25番ポート(SMTP)へのアクセスを許可
# 外部からのTCP465番ポート(SMTPS)へのアクセスを日本からのみ許可
# 外部からのTCP587番ポート(Submission)へのアクセスを日本からのみ許可
# SMTPサーバーを公開する場合のみ
echo "-A INPUT -p tcp --dport 25 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp --dport 465 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp --dport 587 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG

# 25番ポート(smtp)に対して1分に8回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 25 -m hashlimit --hashlimit-name t_smtp --hashlimit 1/m --hashlimit-burst 8 --hashlimit-mode srcip --hashlimit-htable-expire 900000 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW --dport 25 -j DROP" >> $IPTABLES_CONFIG

# 465番ポート(smtp)に対して1分に8回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 465 -m hashlimit --hashlimit-name t_smtp --hashlimit 1/m --hashlimit-burst 8 --hashlimit-mode srcip --hashlimit-htable-expire 900000 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW --dport 465 -j DROP" >> $IPTABLES_CONFIG

# 587番ポート(submission)に対して1分に8回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 587 -m hashlimit --hashlimit-name t_smtp --hashlimit 1/m --hashlimit-burst 8 --hashlimit-mode srcip --hashlimit-htable-expire 900000 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW --dport 587 -j DROP" >> $IPTABLES_CONFIG

# 外部からのTCP110番ポート(POP3)へのアクセスを日本からのみ許可
# 外部からのTCP995番ポート(POP3S)へのアクセスを日本からのみ許可
# POP3サーバーを公開する場合のみ
echo "-A INPUT -p tcp --dport 110 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp --dport 995 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG

# 外部からのTCP143番ポート(IMAP)へのアクセスを日本からのみ許可
# 外部からのTCP993番ポート(IMAPS)へのアクセスを日本からのみ許可
# IMAPサーバーを公開する場合のみ
echo "-A INPUT -p tcp --dport 143 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp --dport 993 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG

# 110番ポート(pop3)に対して3分に35回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 110 -m hashlimit --hashlimit-name t_pop --hashlimit 3/m --hashlimit-burst 35 --hashlimit-mode srcip --hashlimit-htable-expire 18000000 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW --dport 110 -j DROP" >> $IPTABLES_CONFIG

# 143番ポート(imap)に対して3分に35回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 143 -m hashlimit --hashlimit-name t_imap --hashlimit 3/m --hashlimit-burst 35 --hashlimit-mode srcip --hashlimit-htable-expire 18000000 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW --dport 143 -j DROP" >> $IPTABLES_CONFIG

# 993番ポート(imaps)に対して3分に35回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 993 -m hashlimit --hashlimit-name t_imaps --hashlimit 3/m --hashlimit-burst 35 --hashlimit-mode srcip --hashlimit-htable-expire 18000000 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW --dport 993 -j DROP" >> $IPTABLES_CONFIG

# 995番ポート(pop3s)に対して3分に35回を超えるリクエストは破棄(DoS対策)
echo "-A INPUT -p tcp -m state --state NEW --dport 995 -m hashlimit --hashlimit-name t_pop3s --hashlimit 3/m --hashlimit-burst 35 --hashlimit-mode srcip --hashlimit-htable-expire 900000 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW --dport 995 -j DROP" >> $IPTABLES_CONFIG

# 外部からのUDP1194番ポート(OpenVPN)へのアクセスを日本からのみ許可
# OpenVPNサーバーを公開する場合のみ
#echo "-A INPUT -p udp --dport 1194 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG

# VPNインタフェース用ファイアウォール設定
# OpenVPNサーバーを公開する場合のみ
#[ -f /etc/openvpn/openvpn-startup ] && /etc/openvpn/openvpn-startup

#----------------------------------------------------------#
# 各種サービスを公開する場合の設定(ここまで)               #
#----------------------------------------------------------#

# 拒否IPアドレスからのアクセスはログを記録せずに破棄
# 拒否IPアドレスは/root/deny_ipに1行ごとに記述しておくこと
# (/root/deny_ipがなければなにもしない)
#if [ -s /root/deny_ip ]; then
#    for ip in `cat /root/deny_ip`
#    do
#        echo "-I INPUT -s $ip -j DROP" >> $IPTABLES_CONFIG
#    done
#fi

# 上記のルールにマッチしなかったアクセスはログを記録して破棄
echo "-A INPUT -m limit --limit 1/s -j LOG --log-prefix \"[IPTABLES INPUT] : \"" >> $IPTABLES_CONFIG
echo "-A INPUT -j DROP" >> $IPTABLES_CONFIG
echo "-A FORWARD -m limit --limit 1/s -j LOG --log-prefix \"[IPTABLES FORWARD] : \"" >> $IPTABLES_CONFIG
echo "-A FORWARD -j DROP" >> $IPTABLES_CONFIG

# ファイアウォール設定終了
echo "COMMIT" >> $IPTABLES_CONFIG

echo "Refreshing /etc/iptables/rules.v4 done."
