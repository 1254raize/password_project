$("#new-pass-btn").click(function(){
    $("#new-pass").slideToggle(1000)
});

if($('.password-div').length == 0) {
    $('#password').wrap('<div class="password-div container"><div class="row"><div class="col-11 pass-col"></div></div></div>');
    
    $('.password-div .row').append('<i class="fa-solid fa-eye pass-1 col pass-col align-items-center d-flex" onclick="togglePass()"></i>');
};

if($('.password-confirm-div').length == 0) {
    $('#password_confirm').wrap('<div class="password-confirm-div container"><div class="row"><div class="col-11 pass-col"></div></div></div>');
    $('.password-confirm-div .row').append('<i class="fa-solid fa-eye pass-2 col pass-col align-items-center d-flex" onclick="togglePass()"></i>');
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
};