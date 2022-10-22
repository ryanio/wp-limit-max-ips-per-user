<?php
/**
 * Plugin Name: Limit Max IPs Per User
 * Plugin URI:  https://github.com/ryanio/wp-limit-max-ips-per-user
 * Description: Limit the maximum number of IPs that a user can log in with.
 * Version:     1.5
 * Author:      Ryan Ghods
 * Author URI:  https://ryanio.com 
 * License:     GPL2
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

final class LimitMaxIPsPerUser {
    public static $table_name = 'limit_max_ips_per_user';
    public static $db_ver_option_key = 'limit_max_ips_per_user_db_ver';
    public static $max_ips_option_key = 'limit_max_ips_per_user_max_ips';
    public static $number_of_days_option_key = 'limit_max_ips_per_user_number_of_days';
    public static $email_admin_key = 'limit_max_ips_per_user_email_admin';
    public static $email_user_key = 'limit_max_ips_per_user_email_user';
    public static $truncate_records_scheduled_hook_key = 'limit_max_ips_per_user_truncate_records';

    public static $default_max_ips_value = 10;
    public static $default_number_of_days_value = 3;

    private $db_ver = "1.0";
    private $delete_records_action_name = "limit_max_ips_per_user_delete_records";
    private $delete_records_user_id_option = "limit_max_ips_per_user_user_id_option";
    private $menu_slug = "limit_max_ips_per_user";

    public function __construct() {
        global $wpdb;

        // Get plugin's db version
        $this->installed_db_ver = get_option(self::$db_ver_option_key);

        // Admin acitions
        add_action('admin_init', array($this, 'admin_init') );
        add_action('admin_menu', array($this, 'add_admin_menus') );

        // Actions
        add_action('wp_login', array($this, 'user_login'), 10, 2 );
        add_action('edit_user_profile', array($this, 'edit_user_profile'));
        add_action('wp_ajax_delete_user_ip_records', array($this, 'wp_ajax_delete_user_ip_records'));
        add_action("admin_post_{$this->delete_records_action_name}", array($this, 'admin_post_delete_records'));
        add_action('admin_notices', array($this, 'admin_notices'));
        add_action('admin_enqueue_scripts', array($this, 'admin_enqueue_scripts'));

        // Initialize scheduled events (when someone visits site in front-end)
        add_action('wp', array($this, 'schedule_events'));
        add_action(self::$truncate_records_scheduled_hook_key, array($this, 'truncate_records'));

        // Filters
        add_filter('login_message', array($this, 'user_login_message'));
        add_filter('manage_users_columns', array($this, 'manage_users_columns'));
        add_filter('manage_users_custom_column', array($this, 'manage_users_custom_column'), 10, 3);

        // Check if db needs to be upgraded after plugin update was completed
        add_action('plugins_loaded', array($this, 'update_db_check') );

       // Register deactivation hook 
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

   /**
    * Activate / deactivate / uninstall
    */
    function activate() {
        if (!current_user_can('activate_plugins')) {
            return;
        }

        if (!get_option(self::$max_ips_option_key)) {
            update_option(self::$max_ips_option_key, self::$default_max_ips_value);
        }

        if (!get_option(self::$number_of_days_option_key)) {
            update_option(self::$number_of_days_option_key, self::$default_number_of_days_value);
        }

        $this->create_db();
    }

    function deactivate() {
         if (!current_user_can('activate_plugins')) {
            return;
         }

        self::unschedule_events();
    }

    public static function uninstall() {
         if (!current_user_can('activate_plugins')) {
            return;
         }

        // Delete table
        self::drop_db();

        // Delete options
        self::delete_plugin_options();

        // Remove cron jobs
        self::unschedule_events();
    }

    public static function delete_plugin_options() {
        delete_option(self::$db_ver_option_key);
        delete_option(self::$max_ips_option_key);
        delete_option(self::$number_of_days_option_key);
        delete_option(self::$email_admin_key);
        delete_option(self::$email_user_key);
    }

    public static function unschedule_events() {
        wp_clear_scheduled_hook(self::$truncate_records_scheduled_hook_key);
    }

    public static function drop_db() {
        global $wpdb;
        $table_name = self::$table_name;

        $sql = "DROP TABLE IF EXISTS {$wpdb->prefix}{$table_name};";
        $wpdb->query($sql);
    }

   /**
    * Scheduled events 
    */
    function schedule_events() {
        $number_of_days = get_option(self::$number_of_days_option_key);

        if (!$number_of_days || $number_of_days == 0) {
            wp_clear_scheduled_hook(self::$truncate_records_scheduled_hook_key);
        }

        if(wp_next_scheduled(self::$truncate_records_scheduled_hook_key)) {
        // Already scheduled
            return;
        }

        $start = time();
        wp_schedule_event($start, 'daily', self::$truncate_records_scheduled_hook_key);
    }

    function truncate_records() {
        global $wpdb;
        $table_name = self::$table_name;

        $number_of_days = get_option(self::$number_of_days_option_key);

        if (is_null($number_of_days || $number_of_days == 0)) {
            return;
        }

        $sql = $wpdb->prepare("DELETE FROM {$wpdb->prefix}{$table_name} WHERE time < DATE_SUB(CURDATE(),INTERVAL %d DAY)", $number_of_days);

        $wpdb->query($sql);
    }

   /**
    * Create db
    */
    function create_db() {
        global $wpdb;
        $table_name = self::$table_name;

        if($this->installed_db_ver == $this->db_ver) {
            return;
        }

        // If table exists, return
        if($wpdb->get_row("SHOW TABLES LIKE '{$wpdb->prefix}{$table_name}'")) {
            return;
        }

        $sql = "CREATE TABLE {$wpdb->prefix}{$table_name} (
        id INT(11) NOT NULL AUTO_INCREMENT,
        user_id INT(11) NOT NULL,
        time DATETIME DEFAULT '0000-00-00 00:00:00' NOT NULL,
        ip VARCHAR(100) NOT NULL,
        login_blocked BOOLEAN NOT NULL,
        PRIMARY KEY (id),
        INDEX (user_id, ip)
        );";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        update_option(LimitMaxIPsPerUser::$db_ver_option_key, $this->db_ver);
    }

   /**
    * Checks if the installed database version is the same
    * as the db version of the current plugin and if upgrade is required
    * calls the version specific db upgrade function
    */
    function update_db_check() {
        if (get_option(LimitMaxIPsPerUser::$db_ver_option_key) != $this->db_ver) {
            switch($this->db_ver) {
                case "1.1":
                $this->db_update_1_1();
                break;

                case "1.2":
                $this->db_update_1_2();
                break;
            }
        }
    }

   /**
    * DB version-specific updates
    */
    function db_update_1_1() {
    }

    function db_update_1_2() {
    }

   /**
    * Register settings, sections, and field
    */
    function admin_init() {
        // Register a new section in setting
        add_settings_section('limit_max_ips_per_user_section', 'Settings', array($this, 'limit_max_ips_per_user_callback'), 'limit_max_ips_per_user_settings');

        // Register setting fields
        add_settings_field('limit_max_ips_per_user_max_ips', 'Maximum IPs per user', array($this, 'field_number_max_ips'), 'limit_max_ips_per_user_settings', 'limit_max_ips_per_user_section');
        add_settings_field('limit_max_ips_per_user_number_of_days', 'Number of days for IP limit', array($this, 'field_number_of_days'), 'limit_max_ips_per_user_settings', 'limit_max_ips_per_user_section');
        add_settings_field('limit_max_ips_per_user_email_admin', 'Email Admin', array($this, 'email_admin'), 'limit_max_ips_per_user_settings', 'limit_max_ips_per_user_section');
        add_settings_field('limit_max_ips_per_user_email_user', 'Email User', array($this, 'email_user'), 'limit_max_ips_per_user_settings', 'limit_max_ips_per_user_section');

        // Register new settings
        register_setting('limit_max_ips_per_user_settings', 'limit_max_ips_per_user_max_ips',
            array(
                'type' => 'intval',
                'sanitize_callback' => array($this, 'limit_max_ips_per_user_max_ips_validate')
            ));
        register_setting('limit_max_ips_per_user_settings', 'limit_max_ips_per_user_number_of_days',
            array(
                'type' => 'intval',
                'sanitize_callback' => array($this, 'limit_max_ips_per_user_number_of_days_validate')
            ));
        register_setting('limit_max_ips_per_user_settings', 'limit_max_ips_per_user_email_admin');
        register_setting('limit_max_ips_per_user_settings', 'limit_max_ips_per_user_email_user');
    }

    function add_admin_menus() {
        add_options_page('Limit Max IPs Per User', 'Limit Max IPs Per User', 'manage_options', $this->menu_slug, array($this, 'limit_max_ips_per_user_settings_page'));
    }

    function limit_max_ips_per_user_callback($args) {
    }

    function field_number_max_ips() {
        $max_ips = get_option(LimitMaxIPsPerUser::$max_ips_option_key);

        $output = "<input type=\"number\" id=\"limit_max_ips_per_user_max_ips\" name=\"limit_max_ips_per_user_max_ips\" value=\"{$max_ips}\" class=\"limit-max-ips-per-user\" /> IPs";

        echo $output;
    }

    function limit_max_ips_per_user_max_ips_validate($input) {
        $input = intval($input);

        if (!is_int($input)) {
            add_settings_error('limit_max_ips_per_user_settings', 'limit_max_ips_per_user_max_ips', 'Maximum IPs per user must be a positive number', 'error');
            return self::$default_max_ips_value;

        } elseif ($input <= 0) {
            add_settings_error('limit_max_ips_per_user_settings', 'limit_max_ips_per_user_max_ips', 'Maximum IPs per user must be greater than 0', 'error');
            return self::$default_max_ips_value;
        }

        return $input;
    }

    function limit_max_ips_per_user_number_of_days_validate($input) {
        $input = intval($input);

        if (!is_int($input)) {
            add_settings_error('limit_max_ips_per_user_settings', 'limit_max_ips_per_user_number_of_days', 'Number of days must be a positive number or 0', 'error');
            return self::$default_number_of_days_value;

        } elseif ($input < 0) {
            add_settings_error('limit_max_ips_per_user_settings', 'limit_max_ips_per_user_number_of_days', 'Number of days must be a positive number or 0', 'error');
            return self::$default_number_of_days_value;
        }

        return $input;

    }

    function field_number_of_days() {
        $number_of_days = get_option(LimitMaxIPsPerUser::$number_of_days_option_key);

        $output = "<input type=\"number\" id=\"limit_max_ips_per_user_number_of_days\" name=\"limit_max_ips_per_user_number_of_days\" value=\"{$number_of_days}\" class=\"limit-max-ips-per-user\" /> days";
        $output .= "<p><small><em>The login log below will be truncated to this amount of days to keep the database small and fast.</em></small></p>";

        // Update cron schedule if settings has been updated
        if(isset($_REQUEST['settings-updated'])) {
            wp_clear_scheduled_hook(LimitMaxIPsPerUser::$truncate_records_scheduled_hook_key);
            $this->schedule_events();
        }

        echo $output;
    }

    function email_admin() {
        $email_admin = get_option(LimitMaxIPsPerUser::$email_admin_key);
        $checked = (isset($email_admin) && $email_admin == 1) ? 1 : 0;
    
        $html = '<input type="checkbox" id="limit_max_ips_per_user_email_admin" name="limit_max_ips_per_user_email_admin" value="1"' . checked(1, $checked, false) . '/>';
        $html .= '<label for="limit_max_ips_per_user_email_admin">Email Admin on Blocked Logins</label>';
    
        echo $html;
    }

    function email_user() {
        $email_user = get_option(LimitMaxIPsPerUser::$email_user_key);
        $checked = (isset($email_user) && $email_user == 1) ? 1 : 0;
    
        $html = '<input type="checkbox" id="limit_max_ips_per_user_email_user" name="limit_max_ips_per_user_email_user" value="1"' . checked(1, $checked, false) . '/>';
        $html .= '<label for="limit_max_ips_per_user_email_user">Email User on Blocked Logins</label>';
    
        echo $html;
    }

   /**
    * Enqueue scripts
    */
    function admin_enqueue_scripts($hook) {
        if ($hook == "settings_page_limit_max_ips_per_user") {
            wp_enqueue_style('wp_admin_settings_css', plugins_url('includes/pages/settings/settings.css', __FILE__));
            wp_enqueue_script('wp_admin_settings_js', plugins_url('includes/pages/settings/settings.js', __FILE__));

            // dataTables
            wp_enqueue_style('wp_admin_datatables_css', plugins_url('includes/jquery.dataTables/css/jquery.dataTables.min.css', __FILE__));
            wp_enqueue_script('wp_admin_datatables_jss', plugins_url('includes/jquery.dataTables/js/jquery.dataTables.min.js', __FILE__));

        } else if ($hook == 'user-edit.php') {
            wp_enqueue_style('wp_admin_user_edit_css', plugins_url('includes/pages/user-edit/user-edit.css', __FILE__));
            wp_enqueue_script('wp_admin_user_edit_js', plugins_url('includes/pages/user-edit/user-edit.js', __FILE__));
            add_action('admin_print_scripts', array($this, 'user_edit_inline_js'));
        }
    }

   /**
    * Settings page HTML
    */
    function limit_max_ips_per_user_settings_page() {
       // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        $log = $this->get_log();

        include('includes/pages/settings/settings.php');
    }

   /**
    * User login:
    * Record login IP and check to see
    * if user should be logged out if blocked
    */
    function user_login($user_login, $user = null) {
        if (!$user) {
            $user = get_user_by('login', $user_login);
        }

        if (!$user) {
            // Not logged in
            return;
        }

        $number_of_days = get_option(self::$number_of_days_option_key);
        $max_ips = get_option(self::$max_ips_option_key);
        $email_admin = get_option(self::$email_admin_key);
        $email_user = get_option(self::$email_user_key);
        $number_of_unique_ips = $this->get_ip_count($user->ID, $number_of_days);

        $blocked = false;

        $ip = $this->get_user_ip();
        if ($this->is_unique_ip($user->ID, $ip, $number_of_days)) {
            $number_of_unique_ips++;
        }

        if ($number_of_unique_ips > $max_ips) {
            $blocked = true;
        }

        if (is_super_admin($user->ID)) {
            $blocked = false;
        }

        $this->record_user_login($user, $user_login, $blocked);

        if ($blocked) {
            // Log the user out
            wp_clear_auth_cookie();

            // Email admin if setting is enabled
            if ($email_admin) {
                $to = get_option('admin_email');
                $site_name = get_bloginfo('name');
                $subject = "{$site_name}: Max Login IPs exceeded for {$user->user_login}";
                $user_link = admin_url('user-edit.php?user_id='. $user->ID, 'http');
                $message = "Dear Admin,<br><br>This is a notification to let you know user <a href='{$user_link}'>{$user->user_login}</a> ({$user->user_email}) has exceeded their max login IPs allowed for {$site_name}.<br><br>Note: You can disable this email in your WordPress plugin settings page for <em>Limit Max IPs Per User</em>.";
                $headers = array('Content-Type: text/html; charset=UTF-8');
                wp_mail($to, $subject, $message, $headers);
            }

            // Email user if setting is enabled
            if ($email_user) {
                $to = $user->user_email;
                $site_name = get_bloginfo('name');
                $subject = "{$site_name}: Max Login IPs exceeded for {$user->user_login}";
                $message = "Dear {$user->user_login},<br><br>This is a notification to let you know you have exceeded the max login IPs allowed for {$site_name}.";
                $headers = array('Content-Type: text/html; charset=UTF-8');
                wp_mail($to, $subject, $message, $headers);
            }

            // Build login URL and then redirect
            $login_url = site_url( 'wp-login.php', 'login' );
            $login_url = add_query_arg( 'blocked', '1', $login_url );
            wp_redirect( $login_url );
            exit;
        }
    }

   /**
    * Show a notice to users who try to login and are disabled
    */
    function user_login_message($message) {
        // Show the error message if it seems to be a disabled user
        if (isset($_GET['blocked'] ) && $_GET['blocked'] == 1) { 
            $message = '<div id="login_error">Your account is temporarily disabled for exceeding the number of IPs allowed.</div>';
        }

        return $message;
    }

   /**
    * Record user login in db
    */
    function record_user_login($user, $user_login, $blocked) {
        $ip = $this->get_user_ip();

        $values = array(
            'user_id' => $user->ID,
            'time' => gmdate("Y-m-d\TH:i:s\Z"),
            'ip' => $ip,
            'login_blocked' => $blocked
            );

        $format = array('%d', '%s', '%s', '%d');

        $this->save_data($values, $format);
    }

    function save_data($values, $format) {
        global $wpdb;
        $table_name = self::$table_name;
        $wpdb->insert("{$wpdb->prefix}{$table_name}", $values, $format);
    }

    function get_user_ip() {
        $client = @$_SERVER['HTTP_CLIENT_IP'];
        $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
        $remote = $_SERVER['REMOTE_ADDR'];

        if(filter_var($client, FILTER_VALIDATE_IP)) {
            $ip = $client;
        } elseif(filter_var($forward, FILTER_VALIDATE_IP)) {
            $ip = $forward;
        } else {
            $ip = $remote;
        }

        return $ip;
    }

   /**
    * Get queries
    */
    function get_log() {
        global $wpdb;
        $table_name = self::$table_name;

        $sql = "SELECT * FROM {$wpdb->prefix}{$table_name}";

        $sql .= " INNER JOIN {$wpdb->users} ON {$wpdb->prefix}{$table_name}.user_id = {$wpdb->users}.id";

        $data = $wpdb->get_results($sql, 'ARRAY_A');

        return $data;
    }

    function get_ip_count($user_id = null, $number_of_days = null) {
        global $wpdb;
        $table_name = self::$table_name;

        $sql = "SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}{$table_name}";

        if ($user_id) {
            $sql .= " WHERE user_id = {$user_id}";
        }

        if ($number_of_days) {
            $sql .= " AND time > DATE_SUB(CURDATE(), INTERVAL {$number_of_days} DAY)";
        }

        $count = $wpdb->get_var($sql);

        return $count;
    }

    function is_unique_ip($user_id = null, $ip = null, $number_of_days = null) {
        global $wpdb;
        $table_name = self::$table_name;

        $sql = "SELECT COUNT(*) FROM {$wpdb->prefix}{$table_name}";

        if ($user_id) {
            $sql .= " WHERE user_id = {$user_id} AND ip = '{$ip}'";
        }

        if ($number_of_days) {
            $sql .= " AND time > DATE_SUB(CURDATE(), INTERVAL {$number_of_days} DAY)";
        }

        $count = $wpdb->get_var($sql);

        return $count == 0;
    }

    function get_last_ip_record($user_id) {
        global $wpdb;
        $table_name = self::$table_name;

        $sql = "SELECT ip, time FROM {$wpdb->prefix}{$table_name}";
        $sql .= " WHERE user_id = {$user_id}";
        $sql .= " ORDER BY time DESC";
        $sql .= " LIMIT 1";

        $data = $wpdb->get_results($sql, 'ARRAY_A');

        if(count($data) > 0) {
            return $data[0];
        } else {
            return null;
        }
    }

   /**
    * Delete records
    */
    function admin_post_delete_records() {
        // Verify nonce
        $nonce = isset($_REQUEST['_wpnonce']) ? $_REQUEST['_wpnonce'] : false;
        if (!wp_verify_nonce($nonce, $this->delete_records_action_name)) {
            die('Invalid nonce.');
        }

        if (!isset($_POST['_wp_http_referer'])) {
            die('Missing _wp_http_referer');
        }

        $user_id = isset($_POST[$this->delete_records_user_id_option]) ? $_POST[$this->delete_records_user_id_option] : null;
        $result = $this->delete_records($user_id);

        $url = urldecode($_POST['_wp_http_referer']);
        $url = add_query_arg('delete_ip_records_success', '1', $url);
        wp_safe_redirect($url);
        exit;
    }

    function admin_notices() {
        if (isset($_GET['delete_ip_records_success'])) {
            $class = 'notice notice-success';
            $message = '<strong>Limit Max IPs Per User:</strong> Success deleting records';
            printf('<div class="%1$s"><p>%2$s</p></div>', esc_attr($class), $message); 

        } elseif (isset($_GET['delete_ip_records_error'])) {
            $class = 'notice notice-error';
            $message = '<strong>Limit Max IPs Per User:</strong> Oops, an error occurred doing that!';
            printf('<div class="%1$s"><p>%2$s</p></div>', esc_attr($class), $message); 
        }
    }

    function delete_records($user_id = null) {
        global $wpdb;
        $table_name = self::$table_name;

        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this function.');
        }

        $sql = "DELETE FROM {$wpdb->prefix}{$table_name}";

        if ($user_id) {
            $sql .= " WHERE user_id = {$user_id}";
        }

        return $wpdb->query($sql);
    }

   /**
    * Edit user profile
    */
    function edit_user_profile($user) {
        $number_of_days = get_option(self::$number_of_days_option_key);
        $number_of_unique_ips = $this->get_ip_count($user->ID, $number_of_days);

        $last_ip_record = $this->get_last_ip_record($user->ID);
        if ($last_ip_record) {
            $last_ip_address = $last_ip_record['ip'];
            $last_ip_address_date = $last_ip_record['time'];
        }

        $blocked = false;
        if ($number_of_unique_ips > get_option(self::$max_ips_option_key)) {
            $blocked = true;
        }

        if ($blocked) {
            $blocked_status_string = "<span style='color: red; font-weight: bold;'>Blocked</span>";
        } else {
            $blocked_status_string = "<span style='color: green;'>Not blocked</span>";
        }

        include('includes/pages/user-edit/user-edit.php');
    }

    function user_edit_inline_js() {
        echo "<script type='text/javascript'>";
        echo "var user_id = " . $_GET['user_id'] . ";";
        echo "var _ajax_nonce = '" . wp_create_nonce($this->delete_records_action_name) . "';";
        echo "</script>";
    }

    function wp_ajax_delete_user_ip_records() {
        // Verify nonce
        check_ajax_referer($this->delete_records_action_name);

        if (isset($_POST['user_id'])) {
            $user_id = intval($_POST['user_id']);
        } else {
            die('Invalid user_id');
        }

        $this->delete_records($user_id);

        echo(200);

        wp_die();
    }

   /**
    * User list - custom columns
    */
    function manage_users_columns($defaults) {
        $number_of_days = get_option(self::$number_of_days_option_key);
        $day_string = $number_of_days == 1 ? 'day' : 'days';
        $defaults['limit_max_ips_per_user_unique_ip_count'] = "Unique IP count (past {$number_of_days} {$day_string})";
        return $defaults;
    }

    function manage_users_custom_column($output, $column_name, $user_id) {
        if ($column_name == 'limit_max_ips_per_user_unique_ip_count') {
            $number_of_days = get_option(self::$number_of_days_option_key);
            $count = $this->get_ip_count($user_id, $number_of_days);

            // Don't show count if zero
            if ($count == 0) {
                $count = null;
            }

            return $count;
        }
        return $output;
    }
}

/**
 * Let's go!
 */
$limit_max_ips_per_user = new LimitMaxIPsPerUser();
register_activation_hook(__FILE__, array(&$limit_max_ips_per_user, 'activate'));
register_uninstall_hook(__FILE__, array('LimitMaxIPsPerUser', 'uninstall'));