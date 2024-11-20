// Main JavaScript File for Mobile App Security Tool

// Document Ready Function (Ensures that the DOM is fully loaded before running scripts)
document.addEventListener("DOMContentLoaded", function () {

    // Auto-dismiss Flash Messages after 5 seconds
    const flashMessages = document.querySelectorAll('.alert-dismissible');
    if (flashMessages) {
        setTimeout(() => {
            flashMessages.forEach((message) => {
                const alert = new bootstrap.Alert(message);
                alert.close();
            });
        }, 5000);
    }

    // File Upload Validation (e.g., Check for APK Extension)
    const fileInput = document.getElementById('apk_file');
    if (fileInput) {
        fileInput.addEventListener('change', function () {
            const fileName = this.value;
            const allowedExtensions = /(\.apk)$/i;
            if (!allowedExtensions.exec(fileName)) {
                alert("Invalid file type. Please select an APK file.");
                this.value = ''; // Reset the file input
            }
        });
    }

    // Tooltip Initialization for Elements with Tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.forEach(function (tooltipTriggerEl) {
        new bootstrap.Tooltip(tooltipTriggerEl);
    });

});
