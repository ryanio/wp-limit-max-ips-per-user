<div class="wrap">
    <h1>Limit Max IPs Per User</h1>

    <form method="post" action="options.php">
        <?php
        settings_fields('limit_max_ips_per_user_settings');
        do_settings_sections('limit_max_ips_per_user_settings');
        submit_button('Save Settings');
        ?>
    </form>

    <h2>Login Log</h2>

    <table id="log" class="display" cellspacing="0" width="100%">
        <thead>
            <tr>
                <th>#</th>
                <th>User ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>IP Address</th>
                <th>Time</th>
                <th>Login blocked?</th>
            </tr>
        </thead>
        <tbody>

            <?php foreach ($log as $row) { ?>

            <tr>
                <td><?php echo($row['id']); ?></td>
                <td><?php echo($row['user_id']); ?></td>
                <td><?php echo($row['user_login']); ?></td>
                <td><?php echo($row['user_email']); ?></td>
                <td><?php echo($row['ip']); ?></td>
                <td><?php echo($row['time']); ?> UTC</td>
                <td><?php echo($row['login_blocked'] ? '<span style="color: red;font-weight: bold;">Yes</span>' : 'No'); ?></td>
            </tr>

            <?php } ?>

        </tbody>
    </table>

    <h2>Clear Login Records</h2>

    <div class="clear-login-records">
        <form action="<?php echo(admin_url('admin-post.php')); ?>" method="POST">
            <input type="hidden" name="action" value="<?php echo($this->delete_records_action_name); ?>">
            <?php wp_nonce_field($this->delete_records_action_name); ?>
            <input type="hidden" name="_wp_http_referer" value="<?php echo(urlencode($_SERVER['REQUEST_URI'])); ?>">

            <?php submit_button('Clear Login Records', 'secondary', 'submit', true, array('onclick' => "javascript:return confirm('Are you sure you want to clear all login records? Please note this action cannot be reversed.');")); ?>
            <em>Note: This deletes all recorded IP history and allows everyone to log in again.</em>
        </form>
    </div>

    <h2>Support</h2>
    <p>This plugin is made by Ryan Ghods, you may email him for support inquiries at <a href="mailto:ryan@ryanio.com">ryan@ryanio.com</a>.</p>

    <p>If you'd like to say thanks for this plugin, please consider making a donation via PayPal <a target="_blank" href="https://paypal.me/ryanghods">here</a> :)</p>
</div>