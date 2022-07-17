$("#new-pass-btn").click(function(){
    $("#new-pass").slideToggle(1000)
});

if($('.password-div').length == 0) {
    $('#password').wrap('<div class="password-div container"><div class="row"><div class="col-11 pass-col"></div></div></div>');
    $('#website_password').wrap('<div class="password-div container"><div class="row"><div class="col-11 pass-col"></div></div></div>');
    $('.password-div .row').append('<i class="fa-solid fa-eye pass-1 col pass-col align-items-center d-flex" onclick="togglePass()"></i>');
};

if($('.password-confirm-div').length == 0) {
    $('#password_confirm').wrap('<div class="password-confirm-div container"><div class="row"><div class="col-11 pass-col"></div></div></div>');
    $('#master_password').wrap('<div class="password-confirm-div container"><div class="row"><div class="col-11 pass-col"></div></div></div>');
    $('.password-confirm-div .row').append('<i class="fa-solid fa-eye pass-2 col pass-col align-items-center d-flex" onclick="togglePass()"></i>');
};

//$('#website_password').$('#myID').find(".my-special-class").length
//    prop('onclick', 'toggleNewPass()');
//$('#master_password').prop('onclick', 'toggleNewPass()');

if($('.password-div').find("#website_password").length > 0 && $('.password-div').find(".pass-1").length > 0) {
    var eye = $(".pass-1");
    eye.attr('onclick', 'toggleNewPass()');
}

if($('.password-confirm-div').find("#master_password").length > 0 && $('.password-confirm-div').find(".pass-2").length > 0) {
    var eye = $(".pass-2");
    eye.attr('onclick', 'toggleNewPass()');
}

function toggleEye(target) {
    if(target.hasClass('fa-eye') == true) {
            target.removeClass('fa-eye');
            target.addClass('fa-eye-slash');
        } else {
            target.removeClass('fa-eye-slash');
            target.addClass('fa-eye');
        }
};

function togglePass() {
    var target = $(event.target);
    if(target.hasClass('pass-1') == true) {
        var passField = $('#password');
    } else {
        var passField = $('#password_confirm');
    }

    var type = passField.prop('type');

    if(type === 'password') {
        passField.prop('type', 'text');

    } else {
        passField.prop('type', 'password');
    }
    toggleEye(target);
};

function togglePassEdit() {
    var target = $(event.target);
        if(target.hasClass('edit-pass-1') == true) {
            var passField = $('.password-toggle-1');
        } else {
            var passField = $('.password-toggle-2');
        }

        var type = passField.prop('type');

        if(type === 'password') {
            passField.prop('type', 'text');

        } else {
            passField.prop('type', 'password');
        }
        toggleEye(target);
};

function toggleNewPass() {
    var target = $(event.target);
        if(target.hasClass('pass-1') == true) {
            var passField = $('#website_password');
        } else {
            var passField = $('#master_password');
        }

        var type = passField.prop('type');

        if(type === 'password') {
            passField.prop('type', 'text');

        } else {
            passField.prop('type', 'password');
        }
        toggleEye(target);
};
