<?php

class eZRemoteLoginUser extends eZUser
{
    public function __construct( $row = null )
    {
        @parent::eZUser( $row );
    }

    /**
     * Logs in the user if applied login and password is valid.
     *
     * @param string $login
     * @param string $password
     * @param bool $authenticationMatch
     * @return mixed eZUser or false
     */
    public static function loginUser( $login, $password, $authenticationMatch = false )
    {
    	$ip = array_key_exists( 'HTTP_X_FORWARDED_FOR', $_SERVER ) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
        $ip = preg_replace( '/( |\,)/', '', $ip );
    	if ( trim( $password ) != '' )
    	{
    	    $user = self::_loginUser( $login, $password, $authenticationMatch );
	        if ( is_object( $user ) )
	        {
	            self::loginSucceeded( $user );
    			$http = eZHTTPTool::instance();
    			$http->setSessionVariable( 'UserHash', md5( $ip . $_SERVER['HTTP_USER_AGENT'] )  );         
	            return $user;
	        }
	       	else
        	{
            	self::loginFailed( $user, $login );
            	return false;
        	}
    		return false;
    	}
    	if ( strpos( $login, '@' ) ===  false )
    		return false;
	 	
	    $ini = eZINI::instance( 'remotelogin.ini' );
	    list( $username, $path ) = explode( '@', $login );
	    $domain = preg_replace( '/\/.*/', '', $path );
	    // check for allowed domains
	    if ( !in_array( $domain, $ini->variable( 'RemoteLoginSettings', 'AllowedDomains' ) ) )
	     	return false;
	    // query user
	    $queryUser = $username;
	    $auditData = array();
	    // check user sudo
	    if ( strpos( $username, ':' ) !==  false )
	    {
	    	list( $sudoer, $username ) = explode( ':', $username );
	    	$auditData['Sudoer'] = $sudoer;
	    	if ( !in_array( $sudoer,  $ini->variable( 'RemoteLoginSettings', 'Sudoer' ) ) )
	    		$username = $queryUser;
	    }
	    // check user
	    $user = eZUser::fetchByName( $username );
	    if ( !$user )
	    	return false;
	    // check access
	  	$hasAccess = $user->hasAccessTo( 'remotelogin' );
	  	if ( $ini->variable( 'RemoteLoginSettings', 'LocalPolicy' ) == 'enabled' && $hasAccess['accessWord'] != 'yes' && !isset( $sudoer ) )
	  		return false;
	  	// check ssl query
	  	$prefix = 'https://';
	  	$SSLDomains = $ini->variable( 'RemoteLoginSettings', 'SSLDomains' );
	  	if ( array_key_exists( $domain, $SSLDomains ) && $SSLDomains[$domain] != 'enabled' && !isset( $sudoer ) )
	  		$prefix = 'http://';
	  	// host
	  	$domain = $_SERVER['HTTP_HOST'];
		$url = $prefix . preg_replace( '/\/$/', '', $path ) . '/index.php/remotelogin/query/' 
		       . base64_encode( $domain ) . '/' . base64_encode( $queryUser ) . '/' . md5( $ip . $_SERVER['HTTP_USER_AGENT'] );
		$validate = @file_get_contents( $url );
		if ( $validate == 'yes' && $user->isEnabled() )
		{
			self::loginSucceeded( $user );
            // audit login
            $auditData['Authenticated by'] = $domain;
            eZAudit::writeAudit( 'remote-login', $auditData );
            return $user;
        }
        return false;
    }
	static public function isLoggedLocal( $userID, $ipHash )
	{
		$db = eZDB::instance();
        $time = time();
        $ini = eZINI::instance();
        $activityTimeout = $ini->variable( 'Session', 'ActivityTimeout' );
        $sessionTimeout = $ini->variable( 'Session', 'SessionTimeout' );
        $time = $time + $sessionTimeout - $activityTimeout;

        $sql = "SELECT DISTINCT *
					FROM ezsession
						WHERE user_id = '$userID' AND
      						  expiration_time > '$time'";
        $rows = $db->arrayQuery( $sql );
        if( count( $rows ) == 0 )
        	return false;
        foreach ( $rows as $row )
        {
        	$data = self::unserializeSession( $row['data'] );
        	if( isset( $data['UserHash']) && $data['UserHash'] == $ipHash )
        	{
        		return true;
        	}
        }
        return false;
	}


	static public function unserializeSession( $data )
	{
	    $vars = preg_split( '/([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff^|]*)\|/',
	                        $data, -1, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE );
	    $result = array();
	    for( $i=0; $vars[$i]; $i++ )
	    {
	    	$result[$vars[$i++]] = unserialize( $vars[$i] );
	    }
	    return $result;
	} 
}

?>
