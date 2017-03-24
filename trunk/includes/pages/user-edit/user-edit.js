jQuery('button#delete-ip-records').live('click', function(event) {
    jQuery.post(ajaxurl, {
        'action': 'delete_user_ip_records',
        '_ajax_nonce': _ajax_nonce,
        'user_id': user_id
    }, 
    function(response) {
        console.log(response);
        if (response == 200) {
            jQuery('#limit-max-ips-per-user-ajax-response').html('<div class="notice notice-success inline"><p><strong>Success:</strong> User\'s IP records deleted</p></div>');
            jQuery('button#delete-ip-records').hide();
        } else {
            jQuery('#limit-max-ips-per-user-ajax-response').html('<div class="notice notice-error inline"><p><strong>Error:</strong> Something went wrong deleting the user\'s IP records</p></div>');

        }
    });
});
