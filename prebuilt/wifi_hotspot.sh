#!/sbin/sh
#
# Enable wifi hotspot by youyim
#

OUTFD=$2
if [ -n "$2" ];then
  readlink /proc/$$/fd/$OUTFD 2>/dev/null | grep /tmp >/dev/null
  if [ "$?" -eq "0" ]; then
    # rerouted to log file, we don't want our ui_print commands going there
    OUTFD=0

    # we are probably running in embedded mode, see if we can find the right fd
    # we know the fd is a pipe and that the parent updater may have been started as
    # 'update-binary 3 fd zipfile'
    for FD in `ls /proc/$$/fd`; do
      readlink /proc/$$/fd/$FD 2>/dev/null | grep pipe >/dev/null
      if [ "$?" -eq "0" ]; then
        ps | grep " 3 $FD " | grep -v grep >/dev/null
        if [ "$?" -eq "0" ]; then
          OUTFD=$FD
          break
        fi
      fi
    done
  fi
  ui_print() {
    echo -n -e "ui_print $1\n" >> /proc/self/fd/$OUTFD
    echo -n -e "ui_print\n" >> /proc/self/fd/$OUTFD
  }
else
  ui_print() {
    echo "$1"
  }
fi

mount /system
mount /vendor

ui_print "-Enable wifi hotspot "
if [ -f "/system/vendor/etc/wifi/wifi_concurrency_cfg.txt" ]; then
	ui_print "-Z17..."
	sed -i 's/ENABLE_STA_SAP_CONCURRENCY:0/ENABLE_STA_SAP_CONCURRENCY:1/' /system/vendor/etc/wifi/wifi_concurrency_cfg.txt
elif [ -f "/vendor/etc/wifi/wifi_concurrency_cfg.txt" ]; then
	sed -i 's/ENABLE_STA_SAP_CONCURRENCY:0/ENABLE_STA_SAP_CONCURRENCY:1/' /vendor/etc/wifi/wifi_concurrency_cfg.txt
	umount /vendor
fi

ui_print "- Unmounting /system"
umount /system
