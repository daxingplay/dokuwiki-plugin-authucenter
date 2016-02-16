<?php
/**
 * DokuWiki Plugin authucenter (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  daxingplay <daxingplay@gmail.com>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

require_once(DOKU_INC.'conf/uc.auth.php'); //TODO generate this conf.
require_once(DOKU_INC.'uc_client/client.php');

class auth_plugin_authucenter extends DokuWiki_Auth_Plugin {


    /**
     * Constructor.
     */
    public function __construct() {
        parent::__construct(); // for compatibility

        if (!file_exists(DOKU_INC . 'api/uc.php') || !is_dir(DOKU_INC . 'uc_client') || !file_exists(DOKU_INC . 'conf/uc.auth.php')) {
            msg($this->getLang('ucfilecheckfail'), -1);
            $this->success = false;
            return;
        }

        // FIXME set capabilities accordingly
        $this->cando['addUser']     = false; // can Users be created?
        $this->cando['delUser']     = false; // can Users be deleted?
        $this->cando['modLogin']    = false; // can login names be changed?
        $this->cando['modPass']     = false; // can passwords be changed?
        $this->cando['modName']     = false; // can real names be changed?
        $this->cando['modMail']     = false; // can emails be changed?
        $this->cando['modGroups']   = false; // can groups be changed?
        $this->cando['getUsers']    = false; // can a (filtered) list of users be retrieved?
        $this->cando['getUserCount']= false; // can the number of users be retrieved?
        $this->cando['getGroups']   = false; // can a list of available groups be retrieved?
        $this->cando['external']    = true; // does the module do external auth checking?
        $this->cando['logout']      = true; // can the user logout again? (eg. not possible with HTTP auth)

        // FIXME intialize your auth system and set success to true, if successful
        $this->success = true;
    }


    /**
     * Log off the current user [ OPTIONAL ]
     */
    public function logOff() {
        $this->_uc_setcookie('DW_UCENTER_AUTH', '', -1);
        uc_user_synlogout();
        msg($this->getLang('logoutsuccess'), 0);
    }

    /**
     * Do all authentication [ OPTIONAL ]
     *
     * @param   string  $user    Username
     * @param   string  $pass    Cleartext Password
     * @param   bool    $sticky  Cookie should not expire
     * @return  bool             true on successful auth
     */
    public function trustExternal($user, $pass, $sticky = false) {
        global $USERINFO;
        $sticky ? $sticky = true : $sticky = false; //sanity check

        // do the checking here
        $uid = '';
        $username = '';
        $password = '';
        $email = '';
        $checked = false;
        $user_info = array();

        if(!empty($user)){
            list($uid, $username, $password, $email) = $this->_uc_user_login($user, $pass);
            setcookie('DW_UCENTER_AUTH', '', -86400);
            if($uid > 0){
                $_SERVER['REMOTE_USER'] = $username;
                $user_info = $this->_uc_get_user_full($uid, 1);
                $password = $user_info['password'];
                $this->_uc_setcookie('DW_UCENTER_AUTH', uc_authcode($uid."\t".$user_info['password']."\t".$this->_convert_charset($username), 'ENCODE'));
                uc_user_synlogin($uid);
                $checked = true;
            }else{
                msg($this->getLang('loginfail'), -1);
                $checked = false;
            }
        }else{
            $cookie = $_COOKIE['DW_UCENTER_AUTH'];
            if(!empty($cookie)){
                // use password check instead of username check.
                list($uid, $password, $username) = explode("\t", uc_authcode($cookie, 'DECODE'));
                $username = $this->_convert_charset($username, 0);
                if($password && $uid && $username){
                    // get session info
                    $session = $_SESSION[DOKU_COOKIE]['auth'];
                    if(isset($session) && $session['user'] == $username && $session['password'] == $password){
                        $user_info = $session['info'];
                        $user = $user_info['name'];
                        $email = $user_info['mail'];
                        $group = $user_info['grps'];
                        $checked = true;
                    }else{
                        $user_info = $this->_uc_get_user_full($uid, 1);
                        if($uid == $user_info['uid'] && $password == $user_info['password']){
                            // he has logged in from other uc apps
                            $user = $user_info['username'];
                            $email = $user_info['email'];
                            $checked = true;
                        }
                    }

                }
            }
        }

        if($checked == true){
            $USERINFO['name'] = $user;
            $USERINFO['mail'] = $email;
            $USERINFO['grps'] = array('user');
            $_SERVER['REMOTE_USER'] = $user;
            $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
            $_SESSION[DOKU_COOKIE]['auth']['pass'] = $pass;
            $_SESSION[DOKU_COOKIE]['auth']['password'] = $password;
            $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        }
        return $checked;
    }

    /**
     * Check user+password
     *
     * May be ommited if trustExternal is used.
     *
     * @param   string $user the user name
     * @param   string $pass the clear text password
     * @return  bool
     */
    public function checkPass($user, $pass) {
        return $this->_uc_user_login($user, $pass); // return true if okay
    }

    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
     *
     * @param   string $user the user name
     * @return  array containing user data or false
     */
    public function getUserData($user) {
        $user_info = false;
        if($data = $this->_uc_get_user($user)){
            list($uid, $username, $email) = $data;
            $user_info = array(
                'name' => $username,
                'mail' => $email,
                'grps' => $this->_get_user_group($uid, 1),
                'uid' => $uid
            );
        }
        return $user_info;
    }

    /**
     * Create a new User [implement only where required/possible]
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user HAS TO be added to the default group by this
     * function!
     *
     * Set addUser capability when implemented
     *
     * @param  string     $user
     * @param  string     $pass
     * @param  string     $name
     * @param  string     $mail
     * @param  null|array $grps
     * @return bool|null
     */
    public function createUser($user, $pass, $name, $mail, $grps = null) {
        return $this->_uc_user_register($user, $pass, $mail);
    }

    /**
     * Modify user data [implement only where required/possible]
     *
     * Set the mod* capabilities according to the implemented features
     *
     * @param   string $user    nick of the user to be changed
     * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    public function modifyUser($user, $changes) {
        if(!is_array($changes) || !count($changes)){
            return true;
        }
        $ucresult = $this->_uc_user_edit($user, $_POST['oldpass'], $changes['pass'] ? $changes['pass'] : '', $changes['mail'] ? $changes['mail'] : '');
        $msg = '';
        switch($ucresult){
            case 1:
            case 0:
            case -7:
                return true;
                break;
            case -1:
                $msg = 'wrongpassword';
                break;
            case -4:
                $msg = 'wrongemailformat';
                break;
            case -5:
                $msg = 'emailforbidden';
                break;
            case -6:
                $msg = 'emailregistered';
                break;
            case -8:
                $msg = 'userprotected';
                break;
        }
        msg($this->getLang($msg), -1);
        return false;
    }

    /**
     * Delete one or more users [implement only where required/possible]
     *
     * Set delUser capability when implemented
     *
     * @param   array  $users
     * @return  int    number of users deleted
     */
    public function deleteUsers($users) {
        $count = 0;
        if(is_array($users) && count($users)){
            foreach($users as $user){
                $uid = $this->get_uid($user);
                if($uid && uc_user_delete($uid)){
                    $count++;
                }
            }
        }
        return $count;
    }

    /**
     * Bulk retrieval of user data [implement only where required/possible]
     *
     * Set getUsers capability when implemented
     *
     * @param   int   $start     index of first user to be returned
     * @param   int   $limit     max number of users to be returned
     * @param   array $filter    array of field/pattern pairs, null for no filter
     * @return  array list of userinfo (refer getUserData for internal userinfo details)
     */
    //public function retrieveUsers($start = 0, $limit = -1, $filter = null) {
        // FIXME implement
    //    return array();
    //}

    /**
     * Return a count of the number of user which meet $filter criteria
     * [should be implemented whenever retrieveUsers is implemented]
     *
     * Set getUserCount capability when implemented
     *
     * @param  array $filter array of field/pattern pairs, empty array for no filter
     * @return int
     */
    //public function getUserCount($filter = array()) {
        // FIXME implement
    //    return 0;
    //}

    /**
     * Define a group [implement only where required/possible]
     *
     * Set addGroup capability when implemented
     *
     * @param   string $group
     * @return  bool
     */
    //public function addGroup($group) {
        // FIXME implement
    //    return false;
    //}

    /**
     * Retrieve groups [implement only where required/possible]
     *
     * Set getGroups capability when implemented
     *
     * @param   int $start
     * @param   int $limit
     * @return  array
     */
    //public function retrieveGroups($start = 0, $limit = 0) {
        // FIXME implement
    //    return array();
    //}

    /**
     * Return case sensitivity of the backend
     *
     * When your backend is caseinsensitive (eg. you can login with USER and
     * user) then you need to overwrite this method and return false
     *
     * @return bool
     */
    public function isCaseSensitive() {
        return true;
    }

    /**
     * Sanitize a given username
     *
     * This function is applied to any user name that is given to
     * the backend and should also be applied to any user name within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce username restrictions.
     *
     * @param string $user username
     * @return string the cleaned username
     */
    public function cleanUser($user) {
        return $user;
    }

    /**
     * Sanitize a given groupname
     *
     * This function is applied to any groupname that is given to
     * the backend and should also be applied to any groupname within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce groupname restrictions.
     *
     * Groupnames are to be passed without a leading '@' here.
     *
     * @param  string $group groupname
     * @return string the cleaned groupname
     */
    public function cleanGroup($group) {
        return $group;
    }

    /**
     * Check Session Cache validity [implement only where required/possible]
     *
     * DokuWiki caches user info in the user's session for the timespan defined
     * in $conf['auth_security_timeout'].
     *
     * This makes sure slow authentication backends do not slow down DokuWiki.
     * This also means that changes to the user database will not be reflected
     * on currently logged in users.
     *
     * To accommodate for this, the user manager plugin will touch a reference
     * file whenever a change is submitted. This function compares the filetime
     * of this reference file with the time stored in the session.
     *
     * This reference file mechanism does not reflect changes done directly in
     * the backend's database through other means than the user manager plugin.
     *
     * Fast backends might want to return always false, to force rechecks on
     * each page load. Others might want to use their own checking here. If
     * unsure, do not override.
     *
     * @param  string $user - The username
     * @return bool
     */
    //public function useSessionCache($user) {
      // FIXME implement
    //}

    /**
     * get user id frome ucenter
     *
     * @param  string $username  the name of the user
     * @return int               the user id. 0 on error.
     */
    function get_uid($username){
        $uid = 0;
        if($data = $this->_uc_get_user($username)) {
            $uid = $data[0];
        }
        return $uid;
    }

    private function _get_user_group($user, $is_uid = 0) {
        return array('user');
    }

    /**
     * convert charset
     * @param string $str  the string that to be converted.
     * @param bool   $out  1: doku convert to other char, 0: other char convert to doku
     * @return string converted string.
     */
    private function _convert_charset($str, $out = 1){
        if($this->getConf('uccharset') != 'utf-8'){
            $str = $out ? iconv('utf-8', $this->cnf['charset'], $str) : iconv($this->cnf['charset'], 'utf-8', $str);
        }
        return $str;
    }

    private function _convert_charset_all($arr, $out = 1){
        if($this->getConf('uccharset') != 'utf-8'){
            if(is_array($arr)){
                foreach($arr as $k=>$v){
                    $arr[$k] = $this->_convert_charset_all($v, $out);
                }
            }else{
                $arr = $this->_convert_charset($arr, $out);
            }
        }
        return $arr;
    }

    private function _uc_user_login($username, $password){
        $return = uc_user_login($this->_convert_charset($username), $password);
        return array($return[0], $this->_convert_charset($return[1], 0), $return[2], $return[3], $return[4]);
    }

    private function _uc_get_user($username, $isuid = 0){
        $return = uc_get_user($this->_convert_charset($username), $isuid);
        return array($return[0], $this->_convert_charset($return[1], 0), $return[2]);
    }

    private function _uc_user_register($username, $password, $email){
        return uc_user_register($this->_convert_charset($username), $password, $email);
    }

    private function _uc_user_edit($username, $oldpw, $newpw, $email){
        return uc_user_edit($this->_convert_charset($username), $oldpw, $newpw, $email, 0);
    }

    private function _uc_setcookie($var, $value = '', $life = 0, $httponly = false) {

        $_COOKIE[$var] = $value;

        $timestamp = time();

        if($value == '' || $life < 0) {
            $value = '';
            $life = -1;
        }

        $life = $life > 0 ? $timestamp + $life : ($life < 0 ? $timestamp - 31536000 : 0);
        $path = $httponly && PHP_VERSION < '5.2.0' ? $this->getConf('cookiepath').'; HttpOnly' : $this->getConf('cookiepath');

        $secure = $_SERVER['SERVER_PORT'] == 443 ? 1 : 0;
        if(PHP_VERSION < '5.2.0') {
            setcookie($var, $value, $life, $path, $this->getConf('cookiedomain'), $secure);
        } else {
            setcookie($var, $value, $life, $path, $this->getConf('cookiedomain'), $secure, $httponly);
        }
    }

    private function _uc_get_user_full($username, $isuid = 0){
        global $uc_controls;
        if(empty($uc_controls['user'])){
            require_once(DOKU_INC.'/uc_client/lib/db.class.php');
            require_once(DOKU_INC.'/uc_client/model/base.php');
            require_once(DOKU_INC.'/uc_client/control/user.php');
            $uc_controls['user'] = new usercontrol();
        }
        $args = uc_addslashes(array('username' => $username, 'isuid' => $isuid), 1, TRUE);
        $uc_controls['user']->input = $args;
        $uc_controls['user']->init_input();
        $username = $uc_controls['user']->input('username');
        if(!$uc_controls['user']->input('isuid')) {
            $status = $_ENV['user']->get_user_by_username($username);
        } else {
            $status = $_ENV['user']->get_user_by_uid($username);
        }
        if($status) {
            // do not return salt.
            return array(
                'uid' => $status['uid'],
                'username' => $status['username'],
//                'grps' => $this->_get_user_group($status['uid'], 1),
                'password' => $status['password'],
                'email' => $status['email'],
                'regip' => $status['regip'],
                'regdate' => $status['regdate'],
                'lastloginip' => $status['lastloginip'],
                'lastlogintime' => $status['lastlogintime']
            );
        } else {
            return 0;
        }
    }
}

// vim:ts=4:sw=4:et: