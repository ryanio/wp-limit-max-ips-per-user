<style>
.limit-max-ips-per-user .notice {
    margin-top: 10px;
    margin-bottom: 10px;
}

 .limit-max-ips-per-user .button {
    margin-top: 10px;
    margin-bottom: 3px;
}

</style>

<table class="form-table">
    <tbody>
        <tr class="limit-max-ips-per-user">
            <th>
                Limit Max IPs Per User<br/>
                <small>
                    <em>
                        <a href="<?php echo(admin_url("options-general.php?page={$this->menu_slug}")) ?>" style="font-weight:normal;">Plugin Settings</a>
                    </em>
                </small>
            </th>
            <td>
                <p>
                    <strong>User status:</strong>
                    <?php echo($blocked_status_string); ?><br/>

                    <strong>
                        Number of unique IPs recorded in past
                        <?php echo($number_of_days); ?>
                        <?php echo($number_of_days == 1 ? 'day' : 'days'); ?>:
                    </strong>
                    <?php echo($number_of_unique_ips); ?><br/>

                    <?php if (isset($last_ip_address) && isset($last_ip_address_date)) { ?>
                        <strong>Last unique IP recorded:</strong>
                        <?php echo($last_ip_address); ?> (<?php echo($last_ip_address_date); ?> UTC)
                    <?php } ?>
                </p>

                <p>
                    <div id="limit-max-ips-per-user-ajax-response"></div>
                    <button type="button" id="delete-ip-records" class="button" onclick="javascript:return confirm('Are you sure you want to delete this user\'s login IP records? Please note this action cannot be reversed.');">Clear User's Recorded IPs</button>
                </p>

                <p class="description">
                    <em>Note: Restores user's login access if blocked</em>
                </p>
            </td>
        </tr>
    </tbody>
</table>

<script>
jQuery('button#delete-ip-records').on('click', function(event) {
    jQuery.post(ajaxurl, {
            'action': 'delete_user_ip_records',
            '_ajax_nonce': '<?php echo(wp_create_nonce($this->delete_records_action_name)); ?>',
            'user_id': '<?php echo($user->ID); ?>'
        }, 
        function(response) {
            if (response == 200) {
                jQuery('#limit-max-ips-per-user-ajax-response').html('<div class="notice notice-success inline"><p><strong>Success:</strong> User\'s IP records deleted</p></div>');
                jQuery('button#delete-ip-records').hide();
            } else {
                jQuery('#limit-max-ips-per-user-ajax-response').html('<div class="notice notice-error inline"><p><strong>Error:</strong> Something went wrong deleting the user\'s IP records</p></div>');

            }
        });
});
</script>