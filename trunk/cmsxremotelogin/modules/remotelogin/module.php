<?php
$Module = array( 'name' => 'CMSX Remote Login' );

$ViewList = array();

$ViewList['query'] = array( 'script'        => 'query.php',
    	 					'ui_context'    => 'administration',
    						'params'        => array( 'Domain', 'UserName', 'UserHash' ) );
?>
