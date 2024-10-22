document.addEventListener("DOMContentLoaded", function () {
    // Flash message auto-dismiss after 3 seconds
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(function (message) {
        setTimeout(function () {
            message.style.transition = "opacity 1s";
            message.style.opacity = 0;
            setTimeout(function () {
                message.remove();
            }, 1000);
        }, 3000);
    });

    // Confirmation prompt for deleting items
    const deleteButtons = document.querySelectorAll('.delete-button');
    deleteButtons.forEach(function (button) {
        button.addEventListener('click', function (event) {
            const confirmation = confirm("Are you sure you want to delete this item?");
            if (!confirmation) {
                event.preventDefault();
            }
        });
    });
});
