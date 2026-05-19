#!/bin/bash

#Parse Parameters
TEMP=`getopt hC: "$@"`
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"

DESTDIR=
CONFIGFILE=openssl.cfg

usage()
{
	echo "`basename $0` [-C <configfile>}"
	exit 1
}

while true ; do
	case "$1" in
	-h)	usage; exit 1;;
	
	-C) CONFIGFILE="$2"; shift 2;;

    --)	shift 1; break;;
	
	*)	echo "Unrecognised argument"; usage; exit 1;;
	esac
done

. $CONFIGFILE

UNITSDIR=${DEFAULTOUTPUTROOT}/${LIBDIR}

if [ -n "$1" ]; then
  UNITSDIR=$1
fi

BINDIR=$UNITSDIR/bin

if [ ! -d "$UNITSDIR" ]; then
  echo "Units directory $UNITSDIR is invalid"
  exit 1
fi

mkdir -p $BINDIR

rm $BINDIR/*.ppu $BINDIR/*.o

fpc  -vq -Mdelphi  -FU$BINDIR $COMPILERDEFINES $UNITSDIR/allheaders.pas
if [ $? -ne 0 ]; then exit 2; fi
rm $BINDIR/*.ppu $BINDIR/*.o

fpc  -vq -Mdelphi -FU$BINDIR -dOPENSSL_USE_STATIC_LIBRARY  $COMPILERDEFINES $UNITSDIR/allheaders.pas
if [ $? -ne 0 ]; then exit 2; fi

