<?php

$Module = $Params['Module'];

$domain = base64_decode( trim( $Params['Domain'] ) );

$userName = base64_decode( trim( $Params['UserName'] ) );

$userHash = trim( $Params['UserHash'] );

$ini = eZINI::instance( 'remotelogin.ini' );

if( trim( $ini->variable( 'RemoteLoginSettings', 'RemoteRestrictByIP' ) ) == 'enabled' )
{
	$ip = array_key_exists( 'HTTP_X_FORWARDED_FOR', $_SERVER ) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
    $ip = preg_replace( '/( |\,)/', '', $ip );
	if ( !in_array( $ip,  $ini->variable( 'RemoteLoginSettings', 'AllowedIP' ) ) )
	{
		echo "IP $ip not allowed";
		eZExecution::cleanExit();
	}
}

if( $domain != '' && $userName != '' && $userHash != '' )
{
	$queryUser = $userName;
	$isLogged  = false;
    if ( strpos( $userName, ':' ) !==  false && trim( $ini->variable( 'RemoteLoginSettings', 'Sudo' ) ) == 'enabled' )
	{
	    list( $sudoer, $login ) = explode( ':', $userName );
	    if ( in_array( $sudoer,  $ini->variable( 'RemoteLoginSettings', 'Sudoer' ) ) )
	    	$userName = $sudoer;
	}
	$user = eZUser::fetchByName( $userName );
	if ( $user && eZUser::isUserLoggedIn( $user->id() ) )
	{
	    $hasAccess = $user->hasAccessTo( 'remotelogin' );
	  	if ( $ini->variable( 'RemoteLoginSettings', 'RemotePolicy' ) != 'enabled' || $hasAccess['accessWord'] == 'yes' )
	  	{
			$isLogged = eZRemoteLoginUser::isLoggedLocal( $user->id(), $userHash );
	  	}
	}
	echo $isLogged ? 'yes' :  'no';
	eZAudit::writeAudit( 'remote-verify', array( 'Domain' => $domain, 
												 'User' => $queryUser, 
			                                     'Is Logged' => $isLogged ? 'yes' :  'no' ) );
	eZExecution::cleanExit();
}

eZExecution::cleanExit();
?>