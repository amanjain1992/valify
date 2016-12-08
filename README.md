Valify - Two factor Authentication Plugin
======================================
Valify is multi-factor authentication plugin that uses OTP sent either via SMS , Email or voice

This plugin requires Api key Generated from valify.solutionsinfin.com and need to add on config/setting for plugin section under admin section


##Installation:
To install these plugins use moodle plugin installation interface to upload valify.zip and follow installation steps (use *Authentication method* as plugin type).

Or upload the valify folder to /auth/ directory and follow installation steps after you visit your site's main page.

* Once these plugins are installed, go to ***Site Administration > Users > Accounts > User profile fields*** 

* Now go to ***Site Administration > Plugins > Authentication > Manage authentication*** and enable ***Valify***

* Add an ***Api key*** under plugin section . plugin > manage plugin > settings

Once the authentication method is enable go to the user that you want to force using this auth method and edit their authentication method.

* make sure user have either mobile number (phone) or email Id updated in there account to get OTP

##How to login:
Once the Valify is activated for a user, user need to login from default page once login is successfull user will be redirected to authentication page.
now user need to enter OTP 

You could make this login page the default for all users but make sure user have either have valid email or mobile number
