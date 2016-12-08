<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Another 2-Factor Authentication mehthod to use Google Authenticator time based tokens
 *
 * @package auth_valify
 * @author Aman Jain (aman.j@solutionsinfini.com)
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');

/**
 * Plugin for 2 factor auth.
 */
class auth_plugin_valify extends auth_plugin_base {

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'valify';
        $this->config = get_config('auth/valify');
    }

    /**
     * Old syntax of class constructor. Deprecated in PHP7.
     *
     * @deprecated since Moodle 3.1
     */
    public function auth_plugin_valify() {
        debugging('Use of class name as constructor is deprecated', DEBUG_DEVELOPER);
        self::__construct();
    }

    /**
     * Returns true if the username and password work and sends otp for validation
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login ($username, $password) {
        global $CFG, $DB;
        if ($user = $DB->get_record('user', array('username'=>$username, 'mnethostid'=>$CFG->mnet_localhost_id))) {
            $valid_login  =  validate_internal_user_password($user, $password);
            if($valid_login && $user->auth == 'valify'){
                $api_key = get_config("auth/valify", 'auth_valify_key');
                if (!empty($api_key)) {
                        $curl = curl_init();

                        curl_setopt_array($curl, array(
                        CURLOPT_URL => "api-valify.solutionsinfini.co/v1/?mobile=".$user->phone1."&email=".$user->email,
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_ENCODING => "",
                        CURLOPT_MAXREDIRS => 10,
                        CURLOPT_TIMEOUT => 30,
                        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                        CURLOPT_CUSTOMREQUEST => "POST",
                        CURLOPT_HTTPHEADER => array(
                        "X-Api-Format: json",
                        "X-Api-Method: otp",
                        "X-Auth-Key:".$api_key
                        )
                        ));

                        $response = curl_exec($curl);
                        $err = curl_error($curl);

                        curl_close($curl);
                        if ($err) {
                            redirect($CFG->wwwroot.'/auth/valify/error.php');
                            return false;
                        } else {
                            $response = json_decode($response,true);
                            if ($response['status'] == 'OK') {
                                $token_id = $response['data']['token_id'];
                                $_SESSION['valify_token_id'] = $token_id;
                                $_SESSION['valify_user_validation'] = $user;
                            } else {
                                redirect($CFG->wwwroot.'/auth/valify/error.php');
                                return false;
                            }
                        }
                    return true;
                }
            }
        }
        return false;
    }

    function loginpage_hook() {
    }

    public function user_authenticated_hook(&$user,$username,$password) {
        global $CFG, $OUTPUT;
        if($user->auth == 'valify'){
            if (isset($_SESSION['valify_token_id'])) {
                $token_id = $_SESSION['valify_token_id'];
                redirect($CFG->wwwroot.'/auth/valify/authenticate.php?token_id='.$token_id);
            }
        }
            
    }
    /**
     * Updates the user's password.
     *
     * called when the user password is updated.
     *
     * @param  object  $user        User table object
     * @param  string  $newpassword Plaintext password
     * @return boolean result
     *
     */
    function user_update_password($user, $newpassword) {
        $user = get_complete_user_data('id', $user->id);
        // This will also update the stored hash to the latest algorithm
        // if the existing hash is using an out-of-date algorithm (or the
        // legacy md5 algorithm).
        return update_internal_user_password($user, $newpassword);
    }

    function prevent_local_passwords() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return true;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return true;
    }

    /**
     * Returns true if plugin can be manually set.
     *
     * @return bool
     */
    function can_be_manually_set() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        include "config.html";
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        set_config('auth_valify_key', trim($config->auth_valify_key), 'auth/valify');
        return true;
    }

}


