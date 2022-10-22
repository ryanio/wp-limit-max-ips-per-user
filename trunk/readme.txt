=== Limit Max IPs Per User ===
Contributors: ralxz
Donate link: https://www.paypal.me/ryanghods
Tags: limit, IPs, max, user, security, membership, restrict
Requires at least: 4.6
Tested up to: 6.0
Stable tag: trunk
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Limit the maximum number of IPs a user can log in. Also includes a user login log on the plugin settings page.

== Description ==

Limit the maximum number of IPs a user can log in.

Features:
* Set the maximum number of IPs and the number of days.
* See user login logs and whether their login was blocked or not.
* Reset a specific user's IP history via the `Edit User` page.
* Enable admin or user email notifications when limit exceeded.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/plugin-name` directory, or install the plugin through the WordPress plugins screen directly.
1. Activate the plugin through the 'Plugins' screen in WordPress.
1. Use the Settings->Limit Max IPs Per User screen to configure the plugin.

== Frequently Asked Questions ==

1. **What versions of WordPress, PHP and MySQL does this plugin support?**
    This plugin was developed and tested on **WordPress 4.7.3**, **PHP 5.6.27** and **MySQL 5.6.33**, so those are our recommended minimum supported versions.

    We cannot promise that this plugin will work on older versions of Wordpress, PHP or MySQL, but we try to use best practices in our code to support the most common production environments used today.

== Screenshots ==

1. Plugin settings page
2. User settings page
3. User message if exceeded attempts

== Changelog ==

= 1.5 =
* Small bug fix for other plugins to be able to show data in the user table. Thanks @odoremieux!

= 1.4 =
* Additional bug fix for counting unique IPs on login

= 1.3 =
* Bug fix for counting unique IPs on login

= 1.2 =
* New feature: enable admin or user email notifications when limit exceeded.

= 1.1 =
* Fixes "Clear User's Recorded IPs" button on latest WordPress versions by replacing the deprecated use of jQuery.live('click', ...) with jQuery.on('click', ...)

= 1.0 =
* Initial release

== Upgrade Notice ==

= 1.5 =
* Small bug fix for other plugins to be able to show data in the user table. Thanks @odoremieux!

= 1.4 =
* Additional bug fix for counting unique IPs on login

= 1.3 =
* Bug fix for counting unique IPs on login

= 1.2 =
* New feature: enable admin and user email notifications when limit exceeded.

= 1.1 =
* Bug fix release

= 1.0 =
* Initial release