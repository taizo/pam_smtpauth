#!/bin/sh 

ACLOCAL_FLAGS=""

AUTOMAKE_REQVER="1.7"
ACLOCAL_REQVER="1.7"
AUTOCONF_REQVER="2.58"
AUTOHEADER_REQVER="2.58"
LIBTOOLIZE_REQVER="1.4"


# Usage:
#     compare_versions MIN_VERSION ACTUAL_VERSION
# returns true if ACTUAL_VERSION >= MIN_VERSION
compare_versions() {
    ch_min_version=$1
    ch_actual_version=$2
    ch_status=0
    IFS="${IFS=         }"; ch_save_IFS="$IFS"; IFS="."
    set $ch_actual_version
    for ch_min in $ch_min_version; do
        ch_cur=`echo $1 | sed 's/[^0-9].*$//'`; shift # remove letter suffixes
        if [ -z "$ch_min" ]; then break; fi
        if [ -z "$ch_cur" ]; then ch_status=1; break; fi
        if [ $ch_cur -gt $ch_min ]; then break; fi
        if [ $ch_cur -lt $ch_min ]; then ch_status=1; break; fi
    done
    IFS="$ch_save_IFS"
    return $ch_status
}

# Usage:
#     version_check PACKAGE VARIABLE CHECKPROGS MIN_VERSION SOURCE
# checks to see if the package is available
version_check() {
    vc_package=$1
    vc_variable=$2
    vc_checkprogs=$3
    vc_min_version=$4
    vc_status=1

    vc_checkprog=`eval echo "\\$$vc_variable"`
    if [ -n "$vc_checkprog" ]; then
        echo "using $vc_checkprog for $vc_package"
        return 0
    fi

    echo "checking for $vc_package >= $vc_min_version..."
    for vc_checkprog in $vc_checkprogs; do
        echo $ECHO_N "  testing $vc_checkprog... "
        if $vc_checkprog --version < /dev/null > /dev/null 2>&1; then
            vc_actual_version=`$vc_checkprog --version | head -1 | \
                               sed 's/^.*[      ]\([0-9.]*[a-z]*\).*$/\1/'`
            if compare_versions $vc_min_version $vc_actual_version; then
                echo "found $vc_actual_version"
                # set variable
                eval "$vc_variable=$vc_checkprog"
                vc_status=0
                break
            else
                echo "too old (found version $vc_actual_version)"
            fi
        else
            echo "not found."
        fi
    done
    if [ "$vc_status" != 0 ]; then
        echo "***Error***: You must have $vc_package >= $vc_min_version installed to build."
    fi
    return $vc_status
}

version_check automake AUTOMAKE 'automake automake-1.7' $AUTOMAKE_REQVER || exit
version_check aclocal ACLOCAL 'aclocal aclocal-1.7 aclocal' $ACLOCAL_REQVER  || exit
version_check autoconf AUTOCONF 'autoconf autoconf-2.59 autoconf-2.58 autoconf' $AUTOCONF_REQVER || exit
version_check autoheader AUTOHEADER 'autoheader autoheader-2.59 autoheader-2.58 autoheader' $AUTOHEADER_REQVER || exit
version_check libtoolize LIBTOOLIZE 'libtoolize' $LIBTOOLIZE_REQVER || exit

#exit;
#export AUTOMAKE
#export ACLOCAL
#export AUTOCONF
#export AUTOHEADER


${LIBTOOLIZE} -c --ltdl --force || exit 1
${ACLOCAL} ${ACLOCAL_FLAGS} || exit 3
${AUTOHEADER}        || exit 4
${AUTOMAKE} -a -c || exit 5
${AUTOCONF}       || exit 6
./configure --enable-maintainer-mode $*     || exit 7

