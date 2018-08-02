#!/sbin/sh
#
# Delete password on boot
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


# start
ui_print " "
ui_print "**********************"
ui_print "Delete password"
ui_print "**********************"


#ismounted_dm=`mount | grep "/data " | grep "/dm" 2>/dev/null`
#datapart=`find /dev/block -name userdata | grep "by-name/userdata" -m 1 2>/dev/null`
#datatmp=/tmp/data_tmp


ui_print "- Mounting /data"
ismounted=`mount | grep "/data " 2>/dev/null`
if [ -z "$ismounted" ]; then
  mount -o rw /data || ui_print "--- Failure"
  sleep 0.1
fi


ui_print "- Deleting password on boot"
rm -rf "data/system/gatekeeper.password.key" \
       "data/system/gatekeeper.pattern.key" \
       "data/system/locksettings.db" \
       "data/system/locksettings.db-shm" \
       "data/system/locksettings.db-wal" || ui_print "--- Failure"


ui_print "- Unmounting /data"
if [ -z "$ismounted" ]; then
  umount /data
  sleep 0.1
fi

ui_print "- Done !"
ui_print " "

exit 0
