<?php
/**
 * Options for the authucenter plugin
 *
 * @author daxingplay <daxingplay@gmail.com>
 */


$meta['uccharset'] = array('string');
$meta['cookiepath'] = array('string');
$meta['cookiedomain'] = array('string');
$meta['cookiename'] = array('string');
$meta['regenerateconfig'] = array('onoff');
$meta['ucappconfig'] = array('', '_pattern' => "/define\('UC_[A-Z_]+',\s*'[^']*'\);\s*\n*/m");