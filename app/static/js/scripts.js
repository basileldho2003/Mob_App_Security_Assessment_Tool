// Example JavaScript to enhance user interaction and handle form submissions

document.addEventListener("DOMContentLoaded", function () {
    // Example event listener for the upload form
    const uploadForm = document.getElementById("uploadForm");
    if (uploadForm) {
        uploadForm.addEventListener("submit", function (event) {
            const apkFileInput = document.getElementById("apkFile");
            if (!apkFileInput.value) {
                event.preventDefault();
                alert("Please select an APK file before submitting.");
            }
        });
    }

    // Example for showing alerts programmatically
    const alertMessage = document.getElementById("alertMessage");
    if (alertMessage) {
        setTimeout(() => {
            alertMessage.style.display = "none";
        }, 5000); // Hide alert after 5 seconds
    }
});