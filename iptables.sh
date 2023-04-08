#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin

# makerules.sh を先に実行してルールを作成する。
# 設定を反映するだけのスクリプトです。

echo -e "\n"
echo -e "  ############### YOU ARE TRYING TO RELOAD IPTABLES ####################\n"
echo -e "  注意：makerules.shを先に実行してルールを作成しておいてください。"
echo -e "  IPTABLESの設定を再読み込みします。よろしいですか？\n"
echo -e "  WARNING: You have to execute makerules.sh before."
echo -e "  Are you ready to reload configure of IPTABLES? \n"
read -p "  Type y or n :" yn

case $yn in
        [yY]*)
                echo -e "  Reloading iptables.... wait a few mins."
                # 現在の設定をクリア
                #iptables -F
                #iptables -X

                # 設定をリロード
                bash netfilter-persistent reload

                # idsで登録されたipを再度設定。動的FW構築後に有効化する。
                #bash /root/atcheck.sh
                
                echo -e "  IPTABLES reloading done.\n"
        ;;
        *)
                echo -e "\n  Your operation is cancelled."
                exit
        ;;
esac
