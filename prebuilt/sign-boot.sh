#!/sbin/sh

# A lot of this code is copy/paste from SuperSU ZIP and (c) Chainfire & CCMT

# Android Verified Boot Signer (c) Chainfire
# ------------------------------------------
#
# This zip demonstrates how to sign boot images in an Android Verified Boot compliant manner,
# using BootSignature.jar from the AOSP build tree, re-compiled and minified for Android. Due
# to this being Java code, a somewhat functional system partition is required for operation.
# On A/B (slot) partition devices, both system partitions are tried.
#
# Note: this is for the original AVB, AOSP seems to be moving towards a new structure of the
# signatures, and it's accompanying 'avbtool' library.
#
# Note: when used on the Pixel (XL), if you are using TWRP's slot selection, you must be using
# TWRP v3.1.0-RC2 or newer.
#
# -----------
# Custom keys
# -----------
#
# You can generate your own signing keys as follows:
#
# private key:
#     openssl genrsa -f4 -out custom.pem 2048
#     openssl pkcs8 -in custom.pem -topk8 -outform DER -out custom.pk8 -nocrypt
#
# public key:
#     openssl req -new -x509 -sha256 -key custom.pem -out custom.x509.pem
#     openssl x509 -outform DER -in custom.x509.pem -out custom.x509.der
#
# We only need the custom.pk8 and custom.x509.der files.
#
# As far as is currently known, using custom keys only really matters if you OEM/flash lock your
# device.
#
# SuperSU's signing keys will be used by this ZIP by default, but if you add custom.pk8 and
# custom.x509.der to the ZIP these will be used instead.
#
# If /tmp/avb/custom.pk8 and /tmp/avb/custom.x509.der exist, these will override any keys from
# the ZIP. These are ramdisk locations on purpose (and thus require some work on your end), as
# your custom private key should never be stored on your device's flash; and especially not in
# a hard-coded location known by this ZIP. Doing so would completely negate the security benefit
# of using a custom key in the first place.
#
# -----------------------------------------
# For more information and discussion, see:
# https://forum.xda-developers.com/android/software-hacking/signing-boot-images-android-verified-t3600606

OUTFD=$2
ZIP=$3

ui_print() {
  echo -n -e "echo $1\n" > /proc/self/fd/$OUTFD
  echo -n -e "echo\n" > /proc/self/fd/$OUTFD
}

print_warning() {
   echo " "
   echo "Something unexpected has happened. Please pull /tmp/recovery.log and post it to the thread on XDA"
   echo " "
 }

#cleanup() {
  # cleanup

#  cd /
#  rm -rf /tmp/VerifiedBootSigner

  # unmount

#  umount /system
#  umount /system # yes, twice !
#  umount /system_root
#  umount /system_other
#  umount /dev/random

  # print warning
#  if [ "$1" -ne "0" ]; then
#    print_warning
#  fi

  # exit
#  exit $1
#}

echo " "
echo "********************************"
echo "* Android Verified Boot Signer *"
echo "* v8: (c) Chainfire 2017-05-28 *"
echo "********************************"
echo " "

# fix slow RNG on some devices, which may cause some commands to be very slow (kernel/toybox issue)

mount -o bind /dev/urandom /dev/random

# detect slot-based partition layout

SLOT_USED=false
SLOT_SUFFIX=$(getprop ro.boot.slot_suffix 2>/dev/null)
if [ -z "$SLOT_SUFFIX" ]; then
  for i in `cat /proc/cmdline`; do
    if [ "${i%=*}" = "androidboot.slot_suffix" ]; then
      SLOT_SUFFIX=${i#*=}
      break
    fi
  done
fi
if [ ! -z "$SLOT_SUFFIX" ]; then
  SLOT_USED=true
fi

# detect system device
# seems convoluted, but this script snippet is carefully crafted so it works on TWRP, patched
# stock boot images, patched stock recovery-inside-boot images, and firmwares that have filesystem
# root inside the /system partition

find_device() {
  FIND_DEVICE_RET=
  local DEVICE=$(cat /fstab.* /etc/fstab | grep -v "#" | grep -m 1 "$1" | tr -s " ");
  if [ -z "$DEVICE" ]; then
    # rare case, only occurs if TWRP boot is incomplete
    DEVICE=$(cat /etc/recovery.fstab | grep -v "#" | grep -m 1 "$2" | tr -s " ")
    if [ ! -z "$DEVICE" ]; then
      local POINT=
      local FS=
      for i in $DEVICE; do
        if [ -z "$POINT" ]; then
          POINT=$i
        elif [ -z "$FS" ]; then
          FS=$i
        else
          DEVICE=$i
          if (! `echo "$DEVICE" | grep '_' >/dev/null`); then
            DEVICE=$i$SLOT_SUFFIX
          fi
          break
        fi
      done
    fi
  fi
  if ($SLOT_USED); then
    if (! `echo $DEVICE | grep slotselect >/dev/null 2>&1`); then
      if (! `echo $DEVICE | grep "$SLOT_SUFFIX" >/dev/null 2>&1`); then
        SLOT_USED=false
      fi
    elif [ -d "/twres" ]; then
      # determine TWRP slot switch, on Pixel/XL needs 3.1.0-RC2+
      for i in $DEVICE; do
        if (`readlink $i >/dev/null 2>&1`); then
          # only supports _X form of slot names right now
          LINK=$(readlink $i)
          SUFFIX=$(echo $LINK | grep -o -e "..\$")
          if [ ! -z "SUFFIX" ]; then
            if (`echo "$SUFFIX" | grep '_' >/dev/null`); then
              SLOT_SUFFIX=$SUFFIX
            fi
          fi
        fi
        break
      done
    fi
    for i in $DEVICE; do
      # remove current slot suffix, only supports _X form of slot names right now
      SUFFIX=$(echo $i | grep -o -e "..\$")
      if (`echo "$SUFFIX" | grep '_' >/dev/null`); then
        i=$(echo $i | sed "s/$SUFFIX//g")
      fi

      if (! `echo $i | grep "$SLOT_SUFFIX" >/dev/null 2>&1`); then
        # add correct slot suffix
        DEVICE=$i$SLOT_SUFFIX
      else
        # slot suffix already included, or no slot suffix
        DEVICE=$i
      fi
      break
    done
  else
    # no slot suffix
    for i in $DEVICE; do
      DEVICE=$i
      break
    done
  fi
  FIND_DEVICE_RET=$DEVICE
}

find_device " / \| /system \| /system_root " "^/system "
SYSTEM_DEVICE=$FIND_DEVICE_RET

SYSTEM_OTHER=
if ($SLOT_USED); then
  # this only supports _a and _b slot names for now
  if [ "$SLOT_SUFFIX" = "_a" ]; then
    SYSTEM_DEVICE_OTHER=`echo $SYSTEM_DEVICE | sed 's/_a/_b/g'`
  elif [ "$SLOT_SUFFIX" = "_b" ]; then
    SYSTEM_DEVICE_OTHER=`echo $SYSTEM_DEVICE | sed 's/_b/_a/g'`
  fi
  if [ ! -z "$SYSTEM_DEVICE_OTHER" ]; then
    mkdir /system_other
  fi
fi

# mount /system

if (! `mount | grep " /system " >/dev/null 2>&1`); then
  mount -o ro /system
  if (! `mount | grep " /system " >/dev/null 2>&1`); then
    mount -o ro $SYSTEM_DEVICE /system
    if (! `mount | grep " /system " >/dev/null 2>&1`); then
      mount -t ext4 -o ro $SYSTEM_DEVICE /system
    fi
  fi
fi

# if this firmware has filesystem root inside the /system partition, switch things up so we
# get /system_root and /system mounted the Android way rather than the TWRP way

SYSTEM_ROOT_USED=false
if [ -f "/system/sepolicy" ]; then
  SYSTEM_ROOT_USED=true
elif [ -f "/system_root/sepolicy" ]; then
  SYSTEM_ROOT_USED=true
elif [ -f "/system/init.rc" ]; then
  SYSTEM_ROOT_USED=true
elif [ -f "/system_root/init.rc" ]; then
  SYSTEM_ROOT_USED=true
fi

if ($SYSTEM_ROOT_USED); then
  if (! `mount | grep " /system_root " >/dev/null 2>&1`); then
    umount /system
    mkdir /system_root
    mount -o ro $SYSTEM_DEVICE /system_root
    mount -o bind /system_root/system /system
  fi
fi

# detect boot partition

if [ -z "$BOOTIMAGE" ]; then
  for PARTITION in kern-a KERN-A android_boot ANDROID_BOOT kernel KERNEL boot BOOT lnx LNX; do
    BOOTIMAGE=$(readlink /dev/block/by-name/$PARTITION || readlink /dev/block/platform/*/by-name/$PARTITION || readlink /dev/block/platform/*/*/by-name/$PARTITION || readlink /dev/block/by-name/$PARTITION$SLOT_SUFFIX || readlink /dev/block/platform/*/by-name/$PARTITION$SLOT_SUFFIX || readlink /dev/block/platform/*/*/by-name/$PARTITION$SLOT_SUFFIX)
    if [ ! -z "$BOOTIMAGE" ]; then break; fi
  done
fi

if [ -z "$BOOTIMAGE" ]; then
  BOOTIMAGE=$(cat /etc/recovery.fstab | grep -v "#" | grep -m 1 "^/boot" | tr -s " " | cut -f 3 -d " " | grep "/dev/block")
fi

# print info

echo "System: $SYSTEM_DEVICE"
if ($SYSTEM_ROOT_USED); then
  echo "Filesystem root inside /system"
fi
echo "Boot: $BOOTIMAGE"
echo " "

if [ -z "$BOOTIMAGE" ]; then
  echo "Abort: boot image not found"
#  cleanup 1
fi

# extract files

#echo "Extracting files"
#cd /tmp
#rm -rf VerifiedBootSigner
#mkdir VerifiedBootSigner
cd supersu
#unzip -o "$ZIP"

PK8=supersu.pk8
X509=supersu.x509.der

if [ -f "custom.pk8" ]; then
  if [ -f "custom.x509.der" ]; then
    PK8=custom.pk8
    X509=custom.x509.der
  fi
fi
if [ -f "/tmp/avb/custom.pk8" ]; then
  if [ -f "/tmp/avb/custom.x509.der" ]; then
    PK8=/tmp/avb/custom.pk8
    X509=/tmp/avb/custom.x509.der
  fi
fi

if [ ! -f "BootSignature_Android.jar" ]; then
  echo "Abort: BootSignature_Android.jar not found"
#  cleanup 1
fi
if [ ! -f "$PK8" ]; then
  echo "Abort: $PK8 not found"
#  cleanup 1
fi
if [ ! -f "$X509" ]; then
  echo "Abort: $X509 not found"
#  cleanup 1
fi

# dump boot image, because BootSigner doesn't work on partitions

echo "Dumping boot image"

dd if=$BOOTIMAGE of=boot.img
if [ ! -f "boot.img" ]; then
  echo "Abort: boot.img not found"
#  cleanup 1
fi

# unset LD_LIBRARY_PATH
# dex2oat (may be called internally, even though we ask dalvikvm not to) can be 32-bit while
# dalvikvm is 64-bit, prevent possible conflicts by letting the linker decide which paths to use,
# rather than forcing our own or using a bad default (TWRP)

unset LD_LIBRARY_PATH

# base command

BOOTSIGNATURE="/system/bin/dalvikvm -Xbootclasspath:/system/framework/core-oj.jar:/system/framework/core-libart.jar:/system/framework/conscrypt.jar:/system/framework/bouncycastle.jar -Xnodex2oat -Xnoimage-dex2oat -cp BootSignature_Android.jar com.android.verity.BootSignature"

# check if boot image already signed

echo "Verifying boot image"

if [ ! -f "/system/bin/dalvikvm" ]; then
  # if we don't have dalvikvm, we want the same behavior as boot.art/oat not found
  RET="initialize runtime"
else
  RET=$($BOOTSIGNATURE -verify boot.img 2>&1)
fi
if (`echo $RET | grep "initialize runtime" >/dev/null 2>&1`); then
  if [ ! -z "$SYSTEM_DEVICE_OTHER" ]; then
    # we do not have a functional boot.art/oat, custom firmwares sometimes do not include a
    # pre-optimized version, and thus require the ROM to have fully booted before all required
    # files are available. it is obviously far outside the scope of this ZIP to manually build the
    # required files. if we are on a slot-based rom, we can see if the other slot has a functional
    # framework
    mount -o ro $SYSTEM_DEVICE_OTHER /system_other
    if [ -d "/system_other/system/framework" ]; then
      # do not use $SYSTEM_ROOT_USED here, different ROM
      mount -o bind /system_other/system /system
    else
      mount -o bind /system_other /system
    fi
    RET=$($BOOTSIGNATURE -verify boot.img 2>&1)
    if (`echo $RET | grep "initialize runtime" >/dev/null 2>&1`); then
      echo "Abort: no functional framework"
#      cleanup 1
    else
      echo "Warning: no functional framework on active slot!"
    fi
  fi
fi

SIGNED=false
if (`echo $RET | grep "VALID" >/dev/null 2>&1`); then
  SIGNED=true
elif (`echo $RET | grep "not signed" >/dev/null 2>&1`); then
  # not signed
  true
elif (`echo $RET | grep "end-of-contents" >/dev/null 2>&1`); then
  # also not signed
  true
elif (`echo $RET | grep "DER length" >/dev/null 2>&1`); then
  # also not signed
  true
elif (`echo $RET | grep "ClassCastException" >/dev/null 2>&1`); then
  # also not signed
  true
else
  # unknown error: also treat as not signed
  echo " "
  echo "Warning: unexpected result"
  echo " "
  ERR=$(echo "$RET" | grep -m 1 "")
  echo "$ERR"
  echo $RET
  print_warning
  echo "Continuing and treating boot image as unsigned"
fi

# sign boot image

echo "Signing boot image"
$BOOTSIGNATURE /boot boot.img $PK8 $X509 boot_signed.img 2>&1

# verify newly signed image

echo "Verifying signed boot image"
RET=$($BOOTSIGNATURE -verify boot_signed.img 2>&1)
if (! `echo $RET | grep "VALID" >/dev/null 2>&1`); then
  echo "Abort: verification failed"
#  cleanup 1
fi

# flash signed boot image

echo "Flashing signed boot image"
cat boot_signed.img /dev/zero | dd of=$BOOTIMAGE bs=4096

# done

echo "Done"
#cleanup 0
exit 0
