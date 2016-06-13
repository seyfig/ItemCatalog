$(document).ready(function () {
    $('#item-form').validate({
        rules: {
            title: {
                required: true
            },
            category_name: {
                required: true,
            }
        },
        highlight: function (element) {
            $(element).closest('.control-group').removeClass('success').addClass('error');
        },
        success: function (element) {
            element.addClass('valid')
                .closest('.control-group').removeClass('error').addClass('success');
        }
    });

})