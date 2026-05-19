#!/bin/bash
HDR=$1

. use.cfg

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

if [ ! -f "${HDR}.tmp" ]; then
  echo "${HDR}.tmp does not exist"
  exit 2
fi


echo "diff of $HDR.h output to $DEFAULTVERNUM/$HDR.h"
diff -u "${SRC}/${HDR}.h" "${HDR}.tmp" > "${DEFAULTVERNUM}/${HDR}.h"
git add "${DEFAULTVERNUM}/${HDR}.h"

