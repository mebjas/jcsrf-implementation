<?php

class csrfProtector
{
	/**
	 * Name of the cookie sent to client
	 */
	public static $cookieName = 'CSRF_AUTH_TOKEN';

	/**
	 * Name of the POST variable sent from client
	 */
	public static $postName = 'CSRF_AUTH_TOKEN';

	/**
	 * expiry time for cookie
	 */
	public static $cookieExpiryTime = 300;	//5 minutes

	/**
	 * flag for cross origin/same origin request
	 */
	public static $isSameOrigin = true;	//5 minutes


	
	/**
	 * function to initialise the csrfProtector work flow
	 */
	public static function initialise()
	{
		//authorise the incoming request
		csrfProtector::authorisePost();
	}

	/**
	 * function to authorise incoming post requests
	 */
	public static function authorisePost($logging = true, $action = 0)
	{
		//#todo this method is valid for same origin request only
		//for cross origin the functionality is different
		if ($_SERVER['REQUEST_METHOD'] === 'POST') {

			//currently for same origin only
			if(!(isset($_POST[csrfProtector::$postName]) 
				&& isset($_COOKIE[csrfProtector::$cookieName])
				&& ($_POST[csrfProtector::$postName] === $_COOKIE[csrfProtector::$cookieName])
				)) {

				if($logging) {
					//#todo: perform logging, in default action
				}
				
				switch ($action) {
					case 1:
						//show 404 / 403
						break;
					default:
						unset($_POST);
						break;
				}					
			}
		} 

		/**
		 * in case cookie exist -> refresh it
		 * else create one
		 */
		csrfProtector::refreshCookie();	
	}

	/**
	 * function to refresh cookie sent to browser
	 */
	public static function refreshCookie()
	{
		if(!isset($_COOKIE[csrfProtector::$cookieName])) {
			csrfProtector::createCookie();
		} else {
			//reset the cookie to a longer period
			setcookie(csrfProtector::$cookieName, $_COOKIE[csrfProtector::$cookieName], time() + csrfProtector::$cookieExpiryTime);
		}
	}

	/**
	 * 
	 */
	public static function createCookie()
	{
		setcookie(csrfProtector::$cookieName, csrfProtector::generateAuthToken(128), time() + csrfProtector::$cookieExpiryTime);
	}

	/**
	 * function to generate random hash of length as given in parameter
	 * max length = 128
	 * @param: length to hash required, int
	 */
	public static function generateAuthToken($length = 64)
	{
		//if $length > 128 throw exception #todo 

		if (function_exists("hash_algos") && in_array("sha512", hash_algos())) {
			$token = hash("sha512", mt_rand(0, mt_getrandmax()));
		} else {
			$token=' ';
			for ($i=0;$i<128;++$i)
			{
				$r=mt_rand(0,35);
				if ($r<26)
				{
					$c=chr(ord('a')+$r);
				}
				else
				{ 
					$c=chr(ord('0')+$r-26);
				} 
				$token.=$c;
			}
		}
		return substr($token, 0, $length);
	}
};

