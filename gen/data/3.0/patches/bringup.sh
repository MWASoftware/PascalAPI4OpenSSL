#!/bin/bash

. use.cfg

HDR=$1
if [ -d "${DEFAULTOPENSSL}/include/openssl" ]; then
  SRC="${DEFAULTOPENSSL}/include/openssl"
elif [ -d "${DEFAULTOPENSSL}/openssl" ]; then
  SRC="${DEFAULTOPENSSL}/openssl"
else
  echo "${DEFAULTOPENSSL} is invalid"
  exit 1
fi

if [ ! -f "$SRC/$HDR.h" ]; then
  echo "$SRC/$HDR.h does not exist"
  exit 2
fi

if [ -f $HDR.tmp ]; then
  echo -n "Replace existing $HDR.tmp (Y/n)?"
  read -n 1 RESPONSE
  if [ "$RESPONSE" != "Y" ]; then
    exit 1
  fi
fi

echo "Creating $HDR.tmp"
  
if [ -f "{$DEFAULTVERNUM}/${HDR}.h" ]; then
    patch p0 --follow-symlinks -o $HDR.tmp $SRC/$HDR.h ${DEFAULTVERNUM}/${HDR}.h
elif [ -f "$SRC/$HDR.h" ]; then
  cp $SRC/$HDR.h $HDR.tmp
fi
chmod +w $1.tmp
  
