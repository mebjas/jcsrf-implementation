NoForge 1.0
**************

For documentation on this package, please visit

http://www.seclab.tuwien.ac.at/projects/noforge/


Contents
-----------

This package contains the following files:

- xsrf_proxy.php
  The main program that does most of the work.

- TokenRewriter.java
  A class that dynamically rewrites server replies such that they contain
  a valid token. Requires "HTML Parser" (http://htmlparser.sourceforge.net/).

- sed/
  Contains sed scripts (http://sed.sourceforge.net) that can be used to
  automatically change a protected application such that it does not
  call certain PHP functions, but the wrapper functions defined in
  xsrf_proxy.php. The main script is recurse.sh, its helpers are checksed.sh
  and dosed.sh.


Quick Start
--------------

To apply XSRF protection to your web application, you have to...

1.)

Add an alias to your Apache configuration (or whatever web server
you use) such that all requests to your application are redirected
to xsrf_proxy.php. For instance, if your application is installed
in directory "myapp" in your server's document root, you have to 
add the following alias:

AliasMatch ^/myapp/.*\.php /path/to/xsrf_proxy.php

2.)

Execute the "recurse.sh" script on your web application. This
changes certain calls to builtin PHP functions (such as 
"session_start()" and "die()") to calls of appropriate
wrapper functions inside xsrf_proxy.php. This step is quite reliable
due to its simplicity, but you should begin with a dry run that
only displays the changes that would be performed:

./recurse.sh /path/to/myapp/ check

This displays the lines containing the function calls that are going
to be changed. If the result seems to be OK, you can perform the
transformation with

./recurse.sh /path/to/myapp/ write

3.)

Adjust the application-specific parameters at the beginning of
xsrf_proxy.php (see there). Most notably, this includes the name
that your application uses for storing session ID's (which usually
defaults to PHPSESSID, if you use PHP's session managament functions).


That's it! For more information, please have a look at our paper
(available on our homepage), or hack the source code. Happy protecting!




