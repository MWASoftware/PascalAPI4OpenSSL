#!/bin/bash
#
DEBUG=
DESTROOT=openssl
ALLUNITS=

#Parse Parameters
TEMP=`getopt hdo:C: "$@"`
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"

DESTDIR=
CONFIGFILE=openssl.cfg

while true ; do
	case "$1" in
	-h)	usage; exit 1;;
	
	-d) DEBUG=y; shift 1;;

	-o) DESTDIR="$2"; shift 2;;
	
	-C) CONFIGFILE="$2"; shift 2;;

    --)	shift 1; break;;
	
	*)	echo "Unrecognised argument"; usage; exit 1;;
	esac
done

. $CONFIGFILE

#Remove all includes and focus on expanded header
RemoveSystemIncludes()
{
	local INFILE=$1
	local HEADERFILE="`basename $2`"
	local OUTFN=`mktemp`
	local DOPRINT=
	ALLINCLUDES='\# [0-9]+ *"[a-zA-Z0-9_\/\.\-]+\.h"'
	FNINCLUDES="\# [0-9]+ *\".*\.$HEADERFILE\""
	
	if [ -n "$DEBUG" ]; then
	  echo "Remove System Includes in $INFILE output to $OUTFN"
	  echo "ALLINCLUDES=$ALLINCLUDES"
  	  echo "FNINCLUDES=$FNINCLUDES"
	fi
	#extract lines from expanded header that come from original header
	cat $INFILE |(
		 while read LINE; do
			if [[ "$LINE" =~ $FNINCLUDES ]]; then
			    #echo "Start print $LINE"
				DOPRINT=y
			elif [[ "$LINE" =~ $ALLINCLUDES ]]; then
			    #echo "Stop print $LINE"
				DOPRINT=
			elif [ -n "$DOPRINT" ]; then
			echo "$LINE"
			fi
	done
	) > $OUTFN 
	
	
	cp $OUTFN $INFILE
	rm $OUTFN
	
}
	

PreprocessHeader()
{
  local HEADER=$1
  local INFILE=$2
  local OUTFN=$3
  local INCLUDEDIR=$4
   
# Mark the start of the header file  
  sed -i '1i//...h2pasStart' $INFILE
  
  
#Remove pragma once (gives erroneous warning)    
  sed -i '/^ *# *pragma *once/d' $INFILE
  
#Comment out include files we know don't exist here
if [ -n "$IGNOREINCLUDEFILES" ]; then
  for INC in $IGNOREINCLUDEFILES; do
 #   echo "Excluding $INC"
    sed -i "s/\( *# *include *\(\"$INC\.h\"\|<$INC\.h>\).*\)/\/\/\1/" $INFILE
  done
fi
  
#Hide conditionals from pre-processor
  sed -i 's/\(^ *# *if\)/\/\/h2pas\1/
          s/\(^ *# *el\)/\/\/h2pas\1/
          s/\(^ *# *error\)/\/\/h2pas\1/
          s/\(^ *# *end\)/\/\/h2pas\1/
          /^ *# *include/{p;s/\(# *include\)/\/\/h2pas\1/}' $INFILE

 
#Run the C preprocessor - we convert its output rather than the initial header
  if [ -n "$DEBUG" ]; then
    echo "gcc -dD -E -C -w -I $INCLUDEDIR $INFILE > $OUTFN"
  fi
  
  if ! gcc -dD -E -C -w -I $INCLUDEDIR $INFILE > $OUTFN; then
    echo "gcc failed with error"
#    exit 1
  fi

#Restore hidden conditionals
  sed -i 's/^\/\/h2pas//' $OUTFN  
  
  
  RemoveSystemIncludes $OUTFN $HEADER
  
#Remove anything else before the start of the original header 
  sed -i '1,/\/\/...h2pasStart/d' $OUTFN
 
 
}

#Cleanup pascal output of h2pas
CleanupPascal()
{
  local PASFN=$1
  
 #echo "Cleanup Pascal in $PASFN"
        
         
       
#Remove define DECLARE (already processed)	   
  sed -i '/{ *# *define DECLARE/d' $PASFN
	  

 } 
 

inlist ()
{
	local MEMBER=$1
	local LIST=$2
	
	#echo "Check List $LIST for $MEMBER"
	
	if [ -z "$LIST" ]; then
	  return 1
	fi
	
	for LIST_MEMBER in $LIST; do
	  if [ "$MEMBER" == "$LIST_MEMBER" ]; then
	    return 0
	  fi
	done
	return 1
}

DoH2Pas()
{
	local HEADER=$1
	local DEST=$2
	local INCLUDEDIR=$3
	
	local BN=`basename -s '.h' $HEADER`
    local INFILE=`mktemp /tmp/in.XXXXX.${BN}.h`
    local OUTLOG=`mktemp`
    local PROCESSED_HEADER=`mktemp /tmp/processed.XXXXX.${BN}.h`
    local CPATCHFILE=$CPATCHDIR/"${BN}.h"
    local PPATCHFILE=$PPATCHDIR/"${BN}.pas"
        
	if [ -n "$DEBUG" ]; then
      echo "converting $INFILE to $PASFN"
    else
      echo "converting $HEADER to $PASFN"
    fi
    if [ -f $CPATCHFILE ]; then
	  patch -p0 --follow-symlinks -o $INFILE $HEADER $CPATCHFILE
    else
      cp $HEADER $INFILE
    fi
    
  	PreprocessHeader $HEADER $INFILE $PROCESSED_HEADER $INCLUDEDIR 	  	  

	
	if [ -n "$DEBUG" ]; then
	  echo "$H2PAS -o $DEST -u $BN -C $H2PASCONFIG $PROCESSED_HEADER"
	fi
	
	export H2P_BANNER="  Generated from OpenSSL $VERNUM Header File `basename $HEADER` - `date`
  $BANNEREXTRA"
	SYNTAXERROR=
	$H2PAS -o $DEST -u $BN -C $H2PASCONFIG $PROCESSED_HEADER |tee $OUTLOG
	H2PASEXITCODE=${PIPESTATUS[0]}
	if [ $H2PASEXITCODE -eq 1 ]; then
	  SYNTAXERROR=Y
	elif [ $H2PASEXITCODE -gt 1 ]; then
	  echo "$H2PAS ended with an error($?)"
	  exit 1
	fi
	
	PASFN=`grep 'Conversion' $OUTLOG|awk '{print $5;}'`
	BN=`grep 'Unit Name is' $OUTLOG|awk '{print $6;}'`
		
	if [ -f $PPATCHFILE ]; then
	  echo "patch -p0  -i $PPATCHFILE $PASFN"
	  patch -p0 -i $PPATCHFILE $PASFN 
	fi
	#Report syntax errors
	#grep '(\* error' -A 3 $PASFN
	
	CleanupPascal $PASFN
	if [ -n "$SYNTAXERROR" ]; then
	  echo "Retaining $PROCESSED_HEADER due to error"
	  rm $INFILE
	elif [ -z "$DEBUG" ]; then 
	  rm $PROCESSED_HEADER $INFILE
    fi
    if [ -n "$BN" ]; then
      ALLUNITS+=" $BN"
    fi
	
	return 0
}

usage ()
{
  echo "$0 [-o <output director>] [-d] [[-C] Configureation fileanme>] <source dir/filename> "
  echo "-o Header output directory {defaults to openssl/headers)"
  echo "-d Debug mode"
}

createAllHeadersFile ()
{
	local DESTDIR=$1
    #Write out all headers file
	(echo "unit allheaders;"
	 echo ""
	 echo "interface"
	 echo ""
	 echo -n "uses "
	 echo -n "$ALLUNITS" | sed 's/^ *//' |sed 's/ /, /g' |fold -s |sed 's/^/     /' |sed '1s/     //'
	 echo ';'
	 echo ""
	 echo "implementation"
	 echo ""
	 echo "end.") >"$DESTDIR/allheaders.pas"
}

SRCDIR=
if [ -z "$1" ]; then
  SRCDIR=$DEFAULTOPENSSL
elif [ -d "$1" ]; then
  SRCDIR=$1
fi

if [ -n "$SRCDIR" ]; then
  if [ -d "$SRCDIR/openssl" ]; then
    SRC=$SRCDIR/openssl
  elif [ -d "$SRCDIR/include/openssl" ]; then
    SRC=$SRCDIR/include/openssl
   else
    echo "$SRCDIR is invalid"
    exit 1
  fi
  INCLUDEDIR=`dirname $SRC`
  VERSRC=$SRC/$VERHDR
else
  if [ -f "$DEFAULTHDRDIR/$1" ]; then
    INFILE="$DEFAULTHDRDIR/$1"
  elif [ -f "$DEFAULTHDRDIR/$1.h" ]; then
    INFILE="$DEFAULTHDRDIR/$1.h"
  elif [ -f "$1" ]; then
    INFILE=$1
  else
    echo "$1 is neither a file nor a directory"
    exit 1
  fi
  INFILEDIR=`dirname $INFILE`
  INCLUDEDIR=`dirname $INFILEDIR`
  VERSRC="`dirname $INFILE`/$VERHDR"
fi

#Determine openssl version
VERSION=`gcc -dD -E $VERSRC 2> /dev/null|grep 'OPENSSL_VERSION_TEXT'|head -n 1|cut -d ' ' -f 4`
if [ -z "$VERSION" ]; then
  echo "Cannot determine OpenSSL Version from $VERSRC"
  exit 1
fi

if [ -z "$DESTDIR" ]; then
  DESTDIR="`pwd`/${DEFAULTOUTPUTROOT}/$VERSION"
fi

VERNUM=`echo "$VERSION"| sed 's/[a-zA-Z]//g'`

echo "Generating Headers for Openssl Version $VERSION From $SRC$INFILE"
echo "Output to $DESTDIR"
echo "Updates from $UPDATESDIR"

mkdir -p $DESTDIR

if [ -n "$INFILE" ]; then
    DoH2Pas $INFILE $DESTDIR $INCLUDEDIR
else
  echo "Processing all in $SRC. Output to $DEST, Patches from $PATCHDIR"
  rm $DESTDIR/*
  for FN in `ls $SRC/*.h`;do
    if ! inlist `basename $FN` "$IGNOREHEADERS"; then
      DoH2Pas $FN $DESTDIR $INCLUDEDIR
      if [ $? -ne 0 ];then
        exit 1
      fi
    else
      echo "Skipping $FN"
    fi
  done
  createAllHeadersFile $DESTDIR
 for DIR in $OTHERFILES; do
    echo "Copying from $DIR to $DESTDIR"
    cp $DIR/*.pas $DESTDIR
    cp $DIR/*.inc $DESTDIR
    cp $DIR/*.txt $DESTDIR
  done
  fi
 
 
