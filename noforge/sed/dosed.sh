#!/bin/bash

# note: you can apply this script multiple times on the same target,
# it will not change more than once

# check for parameters
if (( $# == 0 ))
then 
  echo 'No parameter given' >&2
  exit 1
fi

sed -e 's/\(^\|[[:blank:]]\+\)\(header\|session_start\|session_id\|session_regenerate_id\|setcookie\|setrawcookie\)[[:blank:]]*(/\1_xsrf_\2(/gI' -e 's/\(^\|[[:blank:]]\+\)\(exit\|die\)[[:blank:]]*(/\1_xsrf_exit(/gI' -e 's/\(^\|[[:blank:]]\+\)\(exit\|die\)[[:blank:]]*;/\1_xsrf_exit();/gI' $1 > tmpfile
mv tmpfile $1


# function-syntax of:
# - header
# - session_start
# - session_id
# - session_regenerate_id
# - setcookie
# - setrawcookie
#sed 's/\(^\|[[:blank:]]\+\)\(header\|session_start\|session_id\|session_regenerate_id\|setcookie\|setrawcookie\)[[:blank:]]*(/\1_xsrf_\2(/gI' $1

# function-syntax of:
# - exit
# - die
#sed 's/\(^\|[[:blank:]]\+\)\(exit\|die\)[[:blank:]]*(/\1_xsrf_exit(/gI' $1

# syntax without function braces:
# - exit: 
#   - "exit <something>" is a parse error
#   - exit; is allowed
# - die
#   - "die <something>" is a parse error
#   - "die;" is allowed
#sed 's/\(^\|[[:blank:]]\+\)\(exit\|die\)[[:blank:]]*;/\1_xsrf_exit();/gI' $1
