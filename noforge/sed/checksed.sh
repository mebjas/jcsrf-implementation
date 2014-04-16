#!/bin/bash

# check for parameters
if (( $# == 0 ))
then 
  echo 'No parameter given' >&2
  exit 1
fi

# composition of the two commands below
sed -n -e '/\(^\|[[:blank:]]\+\)\(header\|exit\|die\|session_start\|session_id\|session_regenerate_id\|setcookie\|setrawcookie\)[[:blank:]]*(/Ip' -e '/\(^\|[[:blank:]]\+\)\(exit\|die\)[[:blank:]]*;/Ip' $1

# function-syntax of:
# - header
# - exit
# - die
# - session_start
# - session_id
# - session_regenerate_id
# - setcookie
# - setrawcookie
#sed -n '/\(^\|[[:blank:]]\+\)\(header\|exit\|die\|session_start\|session_id\|session_regenerate_id\|setcookie\|setrawcookie\)[[:blank:]]*(/Ip' $1

# syntax without function braces:
# - exit: 
#   - "exit <something>" is a parse error
#   - exit; is allowed
# - die
#   - "die <something>" is a parse error
#   - "die;" is allowed
#sed -n '/\(^\|[[:blank:]]\+\)\(exit\|die\)[[:blank:]]*;/Ip' $1
