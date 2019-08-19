function init_modals() {

    $('.modal').each(function () {
        if ($(this).hasClass('fv-modal-setup')) {
            return;
        }

        $(this).on('hidden.bs.modal', function () {
            $(this).removeClass('fv-modal-stack');
            $(this).css('z-index', 1050);
            let body_ctrl = $('body');
            body_ctrl.data('fv_open_modals', body_ctrl.data('fv_open_modals') - 1);
            if (body_ctrl.data('fv_open_modals') > 0) {
                body_ctrl.addClass('fv-modal-open');
            }
            else {
                body_ctrl.removeClass('fv-modal-open');
            }
        });

        $(this).on('show.bs.modal', function () {
            let body_ctrl = $('body');
            if (typeof(body_ctrl.data('fv_open_modals')) == 'undefined') {
                body_ctrl.data('fv_open_modals', 0);
            }

            if ($(this).hasClass('fv-modal-stack')) {
                return;
            }

            $(this).addClass('fv-modal-stack');
            body_ctrl.data('fv_open_modals', body_ctrl.data('fv_open_modals') + 1);
        });

        $(this).on('shown.bs.modal', function () {
            let body_ctrl = $('body');
            $(this).css('z-index', 1029 + (10 * body_ctrl.data('fv_open_modals')));
            let modal_backdrop = $('.modal-backdrop');
            modal_backdrop.not('.fv-modal-stack').css('z-index', 1028 + (10 * body_ctrl.data('fv_open_modals')));
            modal_backdrop.addClass('fv-modal-stack');
        });

        $(this).addClass('fv-modal-setup');
    });


}

angular.element(document).ready(function () {
    init_modals();
});
