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
 * Main login page.
 *
 * @package    core
 * @subpackage auth
 * @copyright  1999 onwards Martin Dougiamas  http://dougiamas.com
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require('../../config.php');
require_once('../../login/lib.php');

// Try to prevent searching for sites that allow sign-up.
if (!isset($CFG->additionalhtmlhead)) {
    $CFG->additionalhtmlhead = '';
}
$CFG->additionalhtmlhead .= '<meta name="robots" content="noindex" />';

redirect_if_major_upgrade_required();

$testsession = optional_param('testsession', 0, PARAM_INT); //Test session works properly
$cancel      = optional_param('cancel', 0, PARAM_BOOL);      //Redirect to frontpage, needed for loginhttps

if ($cancel) {
    redirect(new moodle_url('/'));
}

// HTTPS is required in this page when $CFG->loginhttps enabled.
$PAGE->https_required();

$context = context_system::instance();
$PAGE->set_url("$CFG->httpswwwroot/auth/valify/authenticate.php");
$PAGE->set_context($context);
$PAGE->set_pagelayout('login');

// If otp Expires or in case user want to re send th eotp.
if (isset($_REQUEST['resend']) && $_REQUEST['resend'] == 1) {
    $apikey = get_config("auth/valify", 'auth_valify_key');
    $userdetail = $_SESSION['valify_user_validation'];
    $userdetail  = json_decode(json_encode($userdetail), true);
    if (!empty($apikey)) {
        $curl = curl_init();
        curl_setopt_array($curl, array(
        CURLOPT_URL => "https://api-valify.solutionsinfini.com/v1/?mobile=".$userdetail['phone1']."&email=".$userdetail['email'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "POST",
        CURLOPT_HTTPHEADER => array(
        "X-Api-Format: json",
        "X-Api-Method: otp",
        "X-Auth-Key:".$apikey
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
            if ($response['status'] == 'OK'){
                $token_id = $response['data']['token_id'];
                redirect($CFG->wwwroot.'/auth/valify/authenticate.php?token_id='.$token_id);
            } else {
                redirect($CFG->wwwroot.'/auth/valify/error.php');
                return false;
            }
        }
        return true;
    }
}
// Initialize variables.
$errormsg = '';
$errorcode = 0;
$vaildate = false;
if (!empty($_REQUEST['vaildate']) && $_REQUEST['vaildate'] == 1){
    $vaildate = true;
}
if (!empty($_REQUEST['user'])){
    $user = new stdClass();
    $user = json_decode($_REQUEST['user']);
}
if (!empty($_REQUEST['token_id'])){
    $token_id = $_REQUEST['token_id'];
}

if (empty($token_id)){
    redirect($CFG->wwwroot.'/login/index.php');
}
// Validating OTP given by user
if ($vaildate) {
    $curl = curl_init();
    $token = required_param('token', PARAM_TEXT);
    $token_id = required_param('token_id', PARAM_TEXT);

    $apikey = get_config("auth/valify", 'auth_valify_key');
    curl_setopt_array($curl, array(
      CURLOPT_URL => "api-valify.solutionsinfini.com/v1/?token=".$token."&method=otp.verify&token_id=".$token_id,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_ENCODING => "",
      CURLOPT_MAXREDIRS => 10,
      CURLOPT_TIMEOUT => 30,
      CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
      CURLOPT_CUSTOMREQUEST => "POST",
      CURLOPT_HTTPHEADER => array(
        "X-Api-Format: json",
        "X-Api-Method:  otp.verify",
        "X-Auth-Key:".$apikey
      )
    ));

    $response = curl_exec($curl);
    $err = curl_error($curl);

    curl_close($curl);

    if ($err) {
        redirect($CFG->wwwroot.'/auth/valify/error.php');
        return false;
    } else {
        $response =  json_decode($response, true);
        if (!empty($_SESSION['valify_user_validation'])  && $response['status'] =='OK'){
            complete_user_login($_SESSION['valify_user_validation']);
        }
        if (isloggedin() and !isguestuser() && $response['status'] == 'OK') {
            redirect($CFG->wwwroot.'/my/');
        } else {
            notice($response['message'], $CFG->wwwroot.'/auth/valify/authenticate.php?token_id='.$token_id);
        }
    }
}

// Define variables used in page
$site = get_site();

$loginsite = "Authenticate";
$PAGE->navbar->add($loginsite);

// Make sure we really are on the https page when https login required.
$PAGE->verify_https_required();

$PAGE->set_title("$site->fullname: $loginsite");
$PAGE->set_heading("$site->fullname");

echo $OUTPUT->header();

require("index_form.html");
if ($errormsg) {
    $PAGE->requires->js_init_call('M.util.focus_login_error', null, true);
} else if (!empty($CFG->loginpageautofocus)) {
    // Focus username or password.
    $PAGE->requires->js_init_call('M.util.focus_login_form', null, true);
}

echo $OUTPUT->footer();
