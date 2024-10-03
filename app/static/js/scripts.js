document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("uploadForm").addEventListener("submit", function (e) {
        // e.preventDefault(); // Prevent the default form submission

        const formData = new FormData(this);

        fetch('/upload', {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                console.log("Scan completed:", data);
                alert('Scan completed. Check the console for details.');
            })
            .catch(error => {
                console.error("Error:", error);
                alert('There was an error while scanning.');
            });
    });
});
