#!/bin/bash

checkcommand='checksed.sh'
writecommand='dosed.sh'
mypath=`dirname $0`

# expects a directory name as parameter (without trailing slash)
function recurse {

sedcommand="$2"

# for all files / directories in the given directory...
for f in $1/*
do
  if [ -d $f ]
  then
    # echo "Directory: $f, recursing..."
    recurse $f $2
  else
    # you might have to extend this to other extensions as well (e.g., ".inc")
    if [ ${f:(-4)} = '.php' ]
    then
      output=`$sedcommand $f`
      if [ "$output" != '' ]
        then
          echo -e "\nFile: $f"
          echo -e "-----------------\n"
          echo "$output"
      fi
    fi
  fi
done

}

# some sanity checks

if (( $# != 2 ))
then 
  echo "Usage: $0 <directory> <check|write>" >&2
  exit 1
fi

givenDir=$1
if [ ! -d $givenDir ]
then
    echo 'The given directory does not exist.' >&2
    exit 1
fi

mode=$2
if [ $mode = 'check' ]
then sedcommand="$mypath/$checkcommand"
else
    if [ $mode = 'write' ]
    then sedcommand="$mypath/$writecommand"
    else
        echo 'The given mode is not valid.' >&2
        exit 1
    fi
fi

# strip trailing slash from given parameter if present
if [ ${givenDir:(-1)} = '/' ]
then
  givenDirLen=${#givenDir}
  givenDir=${givenDir:0:$givenDirLen-1}
fi

recurse "$givenDir" "$sedcommand"




